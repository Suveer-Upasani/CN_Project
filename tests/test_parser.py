"""Unit tests for Nmap XML parsing without requiring a live network."""

import unittest
from scanner.parser import NmapXMLParser


SAMPLE_XML_WITH_PORTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -p 22,80,443 -oX - 192.168.1.10" start="1695500000" startstr="2026-09-24 11:00:00" version="7.94">
<host starttime="1695500000" endtime="1695500010">
<status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames>
<hostname name="lab-server.local" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22">
  <state state="open" reason="syn-ack" reason_ttl="0"/>
  <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="80">
  <state state="open" reason="syn-ack" reason_ttl="0"/>
  <service name="http" product="Apache httpd" version="2.4.52" extrainfo="(Ubuntu)" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack" reason_ttl="0"/>
  <service name="https" product="Apache httpd" version="2.4.52" extrainfo="(Ubuntu)" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="3306">
  <state state="closed" reason="conn-refused" reason_ttl="0"/>
</port>
</ports>
</host>
<runstats><finished time="1695500010" timestr="2026-09-24 11:00:10" summary="Nmap done"/></runstats>
</nmaprun>
"""

SAMPLE_XML_HOST_DOWN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sn 192.168.1.99" startstr="2026-09-24 11:00:00" version="7.94">
<runstats><finished summary="Nmap done: 1 IP address (0 hosts up) scanned"/></runstats>
</nmaprun>
"""


class TestNmapXMLParser(unittest.TestCase):
    """Test suite for Nmap XML parser."""

    def setUp(self):
        self.parser = NmapXMLParser()

    def test_parse_open_ports_and_services(self):
        """Verify extraction of ports, services, products, versions, and categories."""
        result = self.parser.parse_xml_string(SAMPLE_XML_WITH_PORTS, "192.168.1.10", "192.168.1.10")

        self.assertEqual(result.host_status, "up")
        self.assertEqual(result.resolved_ip, "192.168.1.10")
        self.assertEqual(len(result.ports), 4)
        self.assertEqual(result.total_open_ports, 3)

        # Port 22
        ssh_port = next(p for p in result.ports if p.port == 22)
        self.assertEqual(ssh_port.state, "open")
        self.assertEqual(ssh_port.service, "ssh")
        self.assertEqual(ssh_port.product, "OpenSSH")
        self.assertEqual(ssh_port.version, "8.9p1 Ubuntu")
        self.assertEqual(ssh_port.category, "Remote Access")

        # Port 80
        http_port = next(p for p in result.ports if p.port == 80)
        self.assertEqual(http_port.state, "open")
        self.assertEqual(http_port.service, "http")
        self.assertEqual(http_port.product, "Apache httpd")
        self.assertEqual(http_port.category, "Web")

        # Service groups
        groups = result.service_groups
        self.assertEqual(groups.get("Remote Access"), 1)
        self.assertEqual(groups.get("Web"), 2)

    def test_parse_host_down(self):
        """Verify handling of XML when target host is down / not responding."""
        result = self.parser.parse_xml_string(SAMPLE_XML_HOST_DOWN, "192.168.1.99", "192.168.1.99")
        self.assertEqual(result.host_status, "unreachable")
        self.assertEqual(result.total_open_ports, 0)

    def test_parse_empty_or_malformed_xml(self):
        """Verify parser handles empty or broken XML without raising unhandled exceptions."""
        res_empty = self.parser.parse_xml_string("", "127.0.0.1", "127.0.0.1")
        self.assertEqual(res_empty.host_status, "unreachable")

        res_broken = self.parser.parse_xml_string("<not-xml", "127.0.0.1", "127.0.0.1")
        self.assertEqual(res_broken.host_status, "unreachable")
        self.assertIsNotNone(res_broken.error_message)


if __name__ == "__main__":
    unittest.main()
