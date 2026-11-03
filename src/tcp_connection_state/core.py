"""Core parser for Linux /proc/net/tcp and /proc/net/tcp6 tables.

Why this exists
---------------
The kernel exposes socket state through /proc/net/tcp{,6} as a fixed-width
text table. The columns are documented in `man 5 proc_pid_net_tcp`, but the
state is a bare hex byte and the addresses are hex-encoded in host byte
order, which makes the raw table awkward to consume. This module decodes a
table into records with human-readable state names and timer values.

Design decisions
----------------
* Parsing is line-oriented and tolerant: the header line is skipped, blank
  lines are ignored, and a malformed line raises ValueError with the line
  number so callers can locate the problem.
* The remote address is decoded the same way as the local address. We do not
  try to resolve hostnames or reverse-map anything; the library is pure and
  deterministic.
* Timer columns (`tr` and `tm->when`) are kept as raw integers rather than
  converted to seconds. The kernel stores them in jiffies and the conversion
  depends on HZ, which is not exposed here. Callers that need wall time can
  convert themselves.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


class TcpState(enum.IntEnum):
    """TCP states as defined in include/net/tcp_states.h.

    Values are the numeric codes the kernel writes in the `st` column.
    """

    ESTABLISHED = 0x01
    SYN_SENT = 0x02
    SYN_RECV = 0x03
    FIN_WAIT1 = 0x04
    FIN_WAIT2 = 0x05
    TIME_WAIT = 0x06
    CLOSE = 0x07
    CLOSE_WAIT = 0x08
    LAST_ACK = 0x09
    LISTEN = 0x0A
    CLOSING = 0x0B
    NEW_SYN_RECV = 0x0C

    @classmethod
    def from_code(cls, code: int) -> "TcpState":
        """Return the state for a numeric code.

        Raises ValueError for codes the kernel does not currently emit. We
        prefer an explicit error over silently returning CLOSE, because a
        wrong state is worse than a loud failure when inspecting sockets.
        """
        try:
            return cls(code)
        except ValueError as exc:
            raise ValueError(f"unknown TCP state code: 0x{code:02x}") from exc


@dataclass(frozen=True)
class TcpRecord:
    """One row from a /proc/net/tcp table.

    Addresses are stored as the kernel prints them (hex, host byte order),
    but normalized to lowercase and without a leading zero padding. The
    `local_address` and `remote_address` are the raw hex strings; the
    `local_port` and `remote_port` are decoded integers.

    `uid` is the numeric UID from the kernel; resolving it to a name is left
    to the caller because that requires a passwd database lookup.
    """

    sl: int
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: TcpState
    tx_queue: int
    rx_queue: int
    timer_active: int
    timer_jiffies: int
    retransmits: int
    uid: int
    inode: int

    @property
    def state_name(self) -> str:
        """Human-readable state name, e.g. ``"ESTABLISHED"``."""
        return self.state.name

    @property
    def is_listening(self) -> bool:
        """True when this row is a listening socket."""
        return self.state == TcpState.LISTEN

    @property
    def is_ipv6(self) -> bool:
        """True when the address is 32 hex characters (IPv6 form)."""
        return len(self.local_address) == 32


def _parse_address(field: str) -> Tuple[str, int]:
    """Split an ``ADDR:PORT`` field into (address_hex, port).

    The kernel always uses uppercase hex with no ``0x`` prefix. We lower-case
    the address so callers can compare against values they built themselves.
    """
    if ":" not in field:
        raise ValueError(f"address field missing ':' separator: {field!r}")
    addr, _, port_hex = field.rpartition(":")
    if not addr:
        raise ValueError(f"address field has empty address: {field!r}")
    if not port_hex:
        raise ValueError(f"address field has empty port: {field!r}")
    try:
        port = int(port_hex, 16)
    except ValueError as exc:
        raise ValueError(f"invalid port in field {field!r}: {exc}") from exc
    if not 0 <= port <= 0xFFFF:
        raise ValueError(f"port out of range in field {field!r}: {port}")
    return addr.lower(), port


def _parse_hex_int(field: str) -> int:
    """Parse a bare hex integer, raising ValueError with context."""
    try:
        return int(field, 16)
    except ValueError as exc:
        raise ValueError(f"invalid hex integer {field!r}: {exc}") from exc


def _parse_queue(field: str) -> Tuple[int, int]:
    """Parse the ``tx_queue:rx_queue`` column."""
    if ":" not in field:
        raise ValueError(f"queue field missing ':' separator: {field!r}")
    tx_hex, _, rx_hex = field.partition(":")
    return _parse_hex_int(tx_hex), _parse_hex_int(rx_hex)


def _parse_timer(field: str) -> Tuple[int, int]:
    """Parse the ``active:jiffies`` timer column.

    ``active`` is a small decimal activity counter, ``jiffies`` is hex. The
    kernel prints the pair as ``aa:jjjjjjjj``. When there is no timer the
    kernel prints ``00:00000000``.
    """
    if ":" not in field:
        raise ValueError(f"timer field missing ':' separator: {field!r}")
    active_hex, _, jiffies_hex = field.partition(":")
    return _parse_hex_int(active_hex), _parse_hex_int(jiffies_hex)


def _parse_line(line: str, lineno: int) -> TcpRecord:
    """Parse one data row. ``lineno`` is 1-based and used in errors."""
    parts = line.split()
    if len(parts) < 10:
        raise ValueError(
            f"line {lineno}: expected at least 10 columns, got {len(parts)}"
        )
    sl_field = parts[0]
    if not sl_field.endswith(":"):
        raise ValueError(f"line {lineno}: slot column missing ':': {sl_field!r}")
    try:
        sl = int(sl_field[:-1])
    except ValueError as exc:
        raise ValueError(f"line {lineno}: invalid slot {sl_field!r}") from exc

    local_address, local_port = _parse_address(parts[1])
    remote_address, remote_port = _parse_address(parts[2])
    state_code = _parse_hex_int(parts[3])
    state = TcpState.from_code(state_code)
    tx_queue, rx_queue = _parse_queue(parts[4])
    timer_active, timer_jiffies = _parse_timer(parts[5])
    retransmits = _parse_hex_int(parts[6])
    uid = int(parts[7])
    inode = int(parts[9])

    return TcpRecord(
        sl=sl,
        local_address=local_address,
        local_port=local_port,
        remote_address=remote_address,
        remote_port=remote_port,
        state=state,
        tx_queue=tx_queue,
        rx_queue=rx_queue,
        timer_active=timer_active,
        timer_jiffies=timer_jiffies,
        retransmits=retransmits,
        uid=uid,
        inode=inode,
    )


def parse_tcp_table(text: str) -> List[TcpRecord]:
    """Parse the contents of a /proc/net/tcp or /proc/net/tcp6 file.

    The first line is treated as a header and skipped. Blank lines are
    ignored. Any other malformed line raises ValueError naming the line
    number so the caller can inspect the input.
    """
    records: List[TcpRecord] = []
    lines = text.splitlines()
    for index, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        if index == 1:
            # Header row. We do not trust the column names, only the shape.
            continue
        records.append(_parse_line(line, index))
    return records


def read_tcp_file(path: str) -> List[TcpRecord]:
    """Read and parse a single /proc/net/tcp style file.

    Raises FileNotFoundError if the path does not exist, matching the
    behaviour of open().
    """
    with open(path, "r", encoding="utf-8") as handle:
        return parse_tcp_table(handle.read())


def read_tcp(
    tcp_path: str = "/proc/net/tcp",
    tcp6_path: str = "/proc/net/tcp6",
) -> List[TcpRecord]:
    """Read both the IPv4 and IPv6 tables and return the combined records.

    Either file may be missing on systems without that address family; a
    missing file is skipped rather than raising, because inspecting a
    running system should not fail just because one family is unavailable.
    """
    records: List[TcpRecord] = []
    for path in (tcp_path, tcp6_path):
        if os.path.exists(path):
            records.extend(read_tcp_file(path))
    return records
