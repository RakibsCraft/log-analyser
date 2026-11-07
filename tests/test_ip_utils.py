import pytest

from log_analyser.ip_utils import classify_ip

# Change to True when you start Milestone 2.
STARTED = False
pytestmark = pytest.mark.skipif(not STARTED, reason="Not started")


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.255.255.255", "127.10.20.30"])
def test_loopback(ip):
    assert classify_ip(ip) == "loopback"


@pytest.mark.parametrize("ip", [
    "10.0.0.0", "10.255.255.255", "10.0.0.15",
    "172.16.0.0", "172.20.5.5", "172.31.255.255",
    "192.168.0.0", "192.168.1.20", "192.168.255.255",
])
def test_private(ip):
    assert classify_ip(ip) == "private"


@pytest.mark.parametrize("ip", [
    "203.0.113.45", "8.8.8.8", "0.0.0.0", "255.255.255.255",
    "172.15.255.255",  # just below the 172.16 range
    "172.32.0.0",      # just above the 172.31 range
    "192.167.1.1",
    "11.0.0.1",
])
def test_public(ip):
    assert classify_ip(ip) == "public"


@pytest.mark.parametrize("ip", [
    "", "abc", "10.0.0", "1.2.3.4.5", "256.1.1.1", "1.2.3.-4",
    "1.2.3.4 ", "1..3.4", "a.b.c.d", "2001:db8::1",
])
def test_invalid(ip):
    assert classify_ip(ip) == "invalid"
