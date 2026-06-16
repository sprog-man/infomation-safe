"""
test_pcap.py — PCAP format validation tests

Tests:
  - PCAP global header magic number is 0xa1b2c3d4
  - PCAP record headers have correct structure
  - LINKTYPE_IPV4 (228) is set correctly
  - Binary structure is parseable with struct
"""

import struct
import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network.weather_server import generate_pcap


class TestPCAPFormat(unittest.TestCase):
    """Tests for PCAP binary file format."""

    def _generate_test_pcap(self, city="TestCity"):
        """Helper to generate a test pcap file and return its path."""
        json_data = f'{{"city": "{city}", "temperature_c": 25.0}}'.encode("utf-8")
        return generate_pcap(json_data, city, "captures_test_pcap")

    def test_01_pcap_magic_number(self):
        """PCAP global header starts with little-endian 0xa1b2c3d4."""
        filepath = self._generate_test_pcap()
        try:
            with open(filepath, "rb") as f:
                magic = struct.unpack("<I", f.read(4))[0]
            self.assertEqual(magic, 0xa1b2c3d4)
        finally:
            os.remove(filepath)
            import shutil
            shutil.rmtree("captures_test_pcap", ignore_errors=True)

    def test_02_pcap_version(self):
        """PCAP global header has version 2.4."""
        filepath = self._generate_test_pcap()
        try:
            with open(filepath, "rb") as f:
                data = f.read(8)
            major, minor = struct.unpack("<HH", data[4:8])
            self.assertEqual(major, 2)
            self.assertEqual(minor, 4)
        finally:
            os.remove(filepath)
            import shutil
            shutil.rmtree("captures_test_pcap", ignore_errors=True)

    def test_03_pcap_snaplen(self):
        """PCAP global header snaplen is 65535."""
        filepath = self._generate_test_pcap()
        try:
            with open(filepath, "rb") as f:
                f.seek(16)
                snaplen = struct.unpack("<I", f.read(4))[0]
            self.assertEqual(snaplen, 65535)
        finally:
            os.remove(filepath)
            import shutil
            shutil.rmtree("captures_test_pcap", ignore_errors=True)

    def test_04_pcap_linktype_ipv4(self):
        """PCAP global header LINKTYPE is 228 (LINKTYPE_IPV4)."""
        filepath = self._generate_test_pcap()
        try:
            with open(filepath, "rb") as f:
                f.seek(20)
                linktype = struct.unpack("<I", f.read(4))[0]
            self.assertEqual(linktype, 228)
        finally:
            os.remove(filepath)
            import shutil
            shutil.rmtree("captures_test_pcap", ignore_errors=True)

    def test_05_pcap_record_header(self):
        """PCAP record header has correct timestamp and length fields."""
        filepath = self._generate_test_pcap()
        try:
            with open(filepath, "rb") as f:
                f.read(24)  # Skip global header
                rec_data = f.read(16)
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", rec_data)
            self.assertGreater(ts_sec, 0)  # Valid timestamp
            self.assertEqual(incl_len, orig_len)  # Full capture
        finally:
            os.remove(filepath)
            import shutil
            shutil.rmtree("captures_test_pcap", ignore_errors=True)

    def test_06_pcap_contains_ipv4_header(self):
        """PCAP packet data starts with valid IPv4 header."""
        filepath = self._generate_test_pcap()
        try:
            with open(filepath, "rb") as f:
                f.read(24)  # Global header
                f.read(16)  # Record header
                pkt = f.read(20)  # IPv4 header
            version_ihl = pkt[0]
            self.assertEqual(version_ihl >> 4, 4)  # IPv4
            self.assertEqual(version_ihl & 0x0F, 5)  # IHL = 5 (20 bytes)
        finally:
            os.remove(filepath)
            import shutil
            shutil.rmtree("captures_test_pcap", ignore_errors=True)

    def test_07_pcap_contains_tcp_header(self):
        """PCAP packet data contains TCP header after IPv4."""
        filepath = self._generate_test_pcap()
        try:
            with open(filepath, "rb") as f:
                f.read(24)  # Global header
                f.read(16)  # Record header
                pkt = f.read(40)  # IPv4 (20) + TCP (20)
            ip_header_len = pkt[0] & 0x0F
            tcp_start = ip_header_len * 4
            src_port = struct.unpack(">H", pkt[tcp_start:tcp_start+2])[0]
            self.assertGreater(src_port, 0)  # Valid port
        finally:
            os.remove(filepath)
            import shutil
            shutil.rmtree("captures_test_pcap", ignore_errors=True)

    def test_08_pcap_contains_http_response(self):
        """PCAP packet data contains HTTP response after TCP header."""
        filepath = self._generate_test_pcap("HttpCity")
        try:
            with open(filepath, "rb") as f:
                f.read(24)  # Global header
                f.read(16)  # Record header
                pkt = f.read(300)  # IPv4(20) + TCP(20) + HTTP headers + body
            # HTTP response starts after IP (20) + TCP (20) = 40 bytes from pkt start
            http_part = pkt[40:]
            self.assertIn(b"HTTP/1.1", http_part)
            self.assertIn(b"HttpCity", http_part)
        finally:
            os.remove(filepath)
            import shutil
            shutil.rmtree("captures_test_pcap", ignore_errors=True)

    def test_09_pcap_multiple_records(self):
        """PCAP can contain multiple packet records."""
        json_data = b'{"city": "MultiCity"}'
        filepath = generate_pcap(json_data, "MultiCity", "captures_test_pcap_multi")

        # Generate a second pcap in same dir with different name
        json_data2 = b'{"city": "SecondCity"}'
        filepath2 = generate_pcap(json_data2, "SecondCity", "captures_test_pcap_multi")

        try:
            with open(filepath2, "rb") as f:
                content = f.read()

            # Should have: global header + record1 + record2
            f2 = open(filepath2, "rb")
            f2.read(24)  # Global
            f2.read(16)  # Record 1
            rec2 = f2.read(16)  # Record 2
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", rec2)
            self.assertGreater(incl_len, 0)
            f2.close()
        finally:
            os.remove(filepath)
            os.remove(filepath2)
            import shutil
            shutil.rmtree("captures_test_pcap_multi", ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
