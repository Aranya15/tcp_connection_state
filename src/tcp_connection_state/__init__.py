"""Parse /proc/net/tcp and /proc/net/tcp6 into structured records.

Public API:
    - TcpState: enum of decoded TCP state names
    - TcpRecord: one parsed connection entry
    - parse_tcp_table: parse a text table into records
    - read_tcp_file: read and parse a file path
    - read_tcp: read and parse both /proc/net/tcp and /proc/net/tcp6
"""

from .core import (
    TcpState,
    TcpRecord,
    parse_tcp_table,
    read_tcp_file,
    read_tcp,
)

__all__ = [
    "TcpState",
    "TcpRecord",
    "parse_tcp_table",
    "read_tcp_file",
    "read_tcp",
]
