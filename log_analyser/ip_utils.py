"""MILESTONE 2: Classify IP addresses.

Knowing whether an attack comes from inside the network or from the internet
changes how a security team responds, so the report labels each IP.
"""


def classify_ip(ip: str) -> str:
    """Return 'loopback', 'private', 'public' or 'invalid' for an IPv4 address.

    Rules:
        loopback: 127.0.0.0 to 127.255.255.255
        private:  10.0.0.0    to 10.255.255.255
                  172.16.0.0  to 172.31.255.255
                  192.168.0.0 to 192.168.255.255
        public:   any other valid IPv4 address
        invalid:  anything that isn't four whole numbers from 0 to 255 joined
                  by dots, e.g. '256.1.1.1', '10.0.0', 'abc', '1.2.3.4.5', ''.
                  IPv6 addresses also count as invalid here.

    Python's ipaddress module can do this, but write it by hand first: splitting
    the string and checking ranges is good practice. You can compare your
    answer with ipaddress afterwards.
    """
    raise NotImplementedError("classify_ip")
