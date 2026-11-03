import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tcp_connection_state import (
    TcpState,
    TcpRecord,
    parse_tcp_table,
    read_tcp_file,
    read_tcp,
)


HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode"
)

SAMPLE = "\n".join(
    [
        HEADER,
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0",
        "   1: 0100007F:1F90 0100007F:1F91 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 4 30 10 -1",
        "   2: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  0        0 12347 1 0000000000000000 100 0 0 10 0",
    ]
)


class ParseTableTests(unittest.TestCase):
    def test_parses_listen_and_established(self):
        records = parse_tcp_table(SAMPLE)
        self.assertEqual(len(records), 3)

        listen = records[0]
        self.assertEqual(listen.sl, 0)
        self.assertEqual(listen.local_address, "0100007f")
        self.assertEqual(listen.local_port, 0x1F90)
        self.assertEqual(listen.remote_port, 0)
        self.assertEqual(listen.state, TcpState.LISTEN)
        self.assertEqual(listen.state_name, "LISTEN")
        self.assertTrue(listen.is_listening)
        self.assertEqual(listen.uid, 1000)
        self.assertEqual(listen.inode, 12345)
        self.assertFalse(listen.is_ipv6)

        established = records[1]
        self.assertEqual(established.state, TcpState.ESTABLISHED)
        self.assertEqual(established.remote_port, 0x1F91)
        self.assertEqual(established.retransmits, 0)
        self.assertFalse(established.is_listening)

        v6 = records[2]
        self.assertTrue(v6.is_ipv6)
        self.assertEqual(v6.local_port, 80)
        self.assertEqual(v6.state, TcpState.LISTEN)

    def test_timer_fields_are_decoded(self):
        line = (
            "   5: 0100007F:0001 0100007F:0002 06 00000000:00000000 "
            "01:0000002A 00000000  0        0 99 1 0 0 0 0 0"
        )
        records = parse_tcp_table(HEADER + "\n" + line)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.state, TcpState.TIME_WAIT)
        self.assertEqual(rec.timer_active, 1)
        self.assertEqual(rec.timer_jiffies, 0x2A)

    def test_queue_values_are_hex(self):
        line = (
            "   7: 0100007F:0001 0100007F:0002 01 00000010:00000020 "
            "00:00000000 00000000  0        0 1 1 0 0 0 0 0"
        )
        records = parse_tcp_table(HEADER + "\n" + line)
        self.assertEqual(records[0].tx_queue, 0x10)
        self.assertEqual(records[0].rx_queue, 0x20)

    def test_blank_lines_are_ignored(self):
        text = HEADER + "\n\n" + SAMPLE.splitlines()[1] + "\n\n"
        records = parse_tcp_table(text)
        self.assertEqual(len(records), 1)

    def test_unknown_state_code_raises(self):
        line = (
            "   0: 0100007F:0001 0100007F:0002 FF 00000000:00000000 "
            "00:00000000 00000000  0        0 1 1 0 0 0 0 0"
        )
        with self.assertRaises(ValueError) as ctx:
            parse_tcp_table(HEADER + "\n" + line)
        self.assertIn("unknown TCP state code", str(ctx.exception))

    def test_malformed_line_reports_line_number(self):
        text = HEADER + "\n" + "garbage\n"
        with self.assertRaises(ValueError) as ctx:
            parse_tcp_table(text)
        self.assertIn("line 2", str(ctx.exception))

    def test_bad_port_field_raises(self):
        line = (
            "   0: 0100007F:ZZZZ 0100007F:0002 01 00000000:00000000 "
            "00:00000000 00000000  0        0 1 1 0 0 0 0 0"
        )
        with self.assertRaises(ValueError):
            parse_tcp_table(HEADER + "\n" + line)

    def test_missing_separator_in_address_raises(self):
        line = (
            "   0: 0100007F0001 0100007F:0002 01 00000000:00000000 "
            "00:00000000 00000000  0        0 1 1 0 0 0 0 0"
        )
        with self.assertRaises(ValueError):
            parse_tcp_table(HEADER + "\n" + line)

    def test_empty_table_returns_empty_list(self):
        self.assertEqual(parse_tcp_table(""), [])
        self.assertEqual(parse_tcp_table(HEADER), [])

    def test_state_from_code_roundtrip(self):
        for state in TcpState:
            self.assertEqual(TcpState.from_code(int(state)), state)


class FileTests(unittest.TestCase):
    def test_read_tcp_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tcp", delete=False) as handle:
            handle.write(SAMPLE)
            path = handle.name
        try:
            records = read_tcp_file(path)
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0].state, TcpState.LISTEN)
        finally:
            os.unlink(path)

    def test_read_tcp_skips_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope")
            records = read_tcp(tcp_path=missing, tcp6_path=missing)
            self.assertEqual(records, [])

    def test_read_tcp_combines_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            v4 = os.path.join(tmp, "tcp")
            v6 = os.path.join(tmp, "tcp6")
            with open(v4, "w", encoding="utf-8") as handle:
                handle.write(HEADER + "\n" + SAMPLE.splitlines()[1] + "\n")
            with open(v6, "w", encoding="utf-8") as handle:
                handle.write(HEADER + "\n" + SAMPLE.splitlines()[3] + "\n")
            records = read_tcp(tcp_path=v4, tcp6_path=v6)
            self.assertEqual(len(records), 2)
            self.assertFalse(records[0].is_ipv6)
            self.assertTrue(records[1].is_ipv6)

    def test_read_tcp_file_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            read_tcp_file("/nonexistent/path/for/tcp_connection_state")


if __name__ == "__main__":
    unittest.main()
