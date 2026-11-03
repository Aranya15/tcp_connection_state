# tcp_connection_state

Parse `/proc/net/tcp` and `/proc/net/tcp6` into structured records with decoded
state names and timer values.

## Usage

```python
from tcp_connection_state import read_tcp, parse_tcp_table

# Read both address families from the running system.
for record in read_tcp():
    print(record.sl, record.local_address, record.local_port,
          record.state_name, record.uid, record.inode)

# Or parse a captured table directly.
records = parse_tcp_table(open("/proc/net/tcp").read())
listening = [r for r in records if r.is_listening]
```

## Why this library exists

The kernel writes TCP connection state into `/proc/net/tcp` as a fixed-width
text table. The state is a bare hex byte (`0A` for `LISTEN`) and the addresses
are hex-encoded in host byte order. Reading the raw table is possible but
annoying: you have to remember that `st` is a hex code, that `tr` and `tm->when`
are two different kinds of number packed into one column, and that the slot
column carries a trailing colon.

This library decodes the table into `TcpRecord` objects with a `TcpState` enum
for the state and integer fields for everything else. The trade-off is that it
stays a pure parser: it does not resolve UIDs to names, does not convert jiffies
to wall-clock seconds, and does not reverse-map addresses. Those conversions
depend on system state (passwd database, `HZ`, DNS) that would make the parser
non-deterministic and harder to test.

## The awkward edge

The timer column is `active:jiffies`, where `active` is a small decimal activity
counter and `jiffies` is a hex value. The kernel prints both as hex in the
`tr`/`tm->when` column, so `01:0000002A` means an active timer with 42 jiffies
remaining. This library keeps `timer_active` and `timer_jiffies` as separate
integers rather than collapsing them into a single duration, because the
jiffies-to-seconds conversion depends on `HZ`, which is not exposed in the
file.

## API

- `TcpState` — `IntEnum` of the kernel's TCP state codes, with
  `TcpState.from_code(code)`.
- `TcpRecord` — frozen dataclass. Fields: `sl`, `local_address`,
  `local_port`, `remote_address`, `remote_port`, `state`, `tx_queue`,
  `rx_queue`, `timer_active`, `timer_jiffies`, `retransmits`, `uid`, `inode`.
  Properties: `state_name`, `is_listening`, `is_ipv6`.
- `parse_tcp_table(text)` — parse a table string into a list of records.
- `read_tcp_file(path)` — read and parse one file.
- `read_tcp(tcp_path="/proc/net/tcp", tcp6_path="/proc/net/tcp6")` — read
  both files, skipping any that do not exist.
