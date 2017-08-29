from __future__ import print_function    # (at top of module)
import socket
import time
import struct
import fcntl
import re

from scapy.sendrecv import send
# from scapy.layers.l2 import ARP
from scapy.layers.inet import UDP, IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
# from scapy.all import send, UDP, IP, ICMP, IPv6, ICMPv6EchoRequest
# from .conf import TIME_FMT

__all__ = ['mac2ipv6', 'get_brdaddr', 'bcast_icmp', 'bcast_icmp6',
           'upnp_probe', 'format_sec', 'normalize_mac']

#TIME_FMT = "%Y-%m-%d %H:%M:%S"


#    Mac:   00:01:2e:6e:6a:fb Link-local:   fe80::201:2eff:fe6e:6afb
#    Mac:   80:56:f2:0a:d5:d7 Link-local:   fe80::8256:f2ff:fe0a:d5d7
# staticmethod
def mac2ipv6(mac):
    """
        Generate LocalLink IPv6 address from Mac
    """
    # only accept MACs separated by a colon
    parts = mac.split(":")

    # modify parts to match IPv6 value
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "%x" % (int(parts[0], 16) ^ 2)

    # format output
    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
    ipv6 = "fe80::%s" % (":".join(ipv6Parts))
    return ipv6


# https://stackoverflow.com/questions/936444/retrieving-network-mask-in-python
def get_brdaddr(ifname):
    """
        Get broadcast for interface
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifname = ifname.encode('utf-8')
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8919, struct.pack('256s', ifname))[20:24])


iface_bcast_addr = None


def bcast_icmp(iface):
    """
       Send broadcast IP4 ping
    """
    global iface_bcast_addr
    if iface_bcast_addr is None:
        iface_bcast_addr = get_brdaddr(iface)
    send(IP(dst=iface_bcast_addr)/ICMP()/"whosthere")


def bcast_icmp6():
    """
       Send broadcast IP6 ping
    """
    send(IPv6(dst="ff02::1")/ICMPv6EchoRequest()/"whosthere")


def upnp_probe():
    """
        send out a series of UPNP probes (IP4 & IP6)
    """
    global iface_bcast_addr

    probe = "M-SEARCH * HTTP/1.1\r\n" \
        "Host:{IP}:1900\r\n" \
        "ST:{ST}\r\n" \
        "Man:\"ssdp:discover\"\r\n" \
        "MX:5\r\n" \
        "USER-AGENT:  OS/version UPnP/1.1 whoshere/1.0\r\n\r\n"

#    if iface_bcast_addr is None:
#        iface_bcast_addr = get_brdaddr(ArpMon.iface)
#    send(IP(dst=iface_bcast_addr) / UDP(sport=1900, dport=1900) / \
#            probe.format("ssdp:all"), loop=2, inter=0.3)
#    time.sleep(.5)
    send(IP(dst="239.255.255.250") / UDP(sport=1900, dport=1900) / \
        probe.format(ST="ssdp:all", IP="239.255.255.250"))
    time.sleep(.5)
    send(IPv6(dst="ff02::c") / UDP(sport=1900, dport=1900) / \
        probe.format(ST="ssdp:all", IP="[ff02::c]"))


def format_sec(total_seconds):
    """
        args: seconds
        returns: H:MM:SS
    """
    m, s = divmod(total_seconds, 60)
    h, m = divmod(int(m), 60)
    return "{:d}:{:02d}:{:.2f}".format(h, m, s)


def normalize_mac(eaddr):
    a = re.split('-|:', eaddr)
    if len(a) != 6:
        raise ValueError("invalid mac")
#    if sum(map(len, a)) != 12:
#       raise ValueError("invalid mac")
    mac = ":".join([i.zfill(2) for i in a]).lower()
    return mac

#
# Do nothing
# (syntax check)
#
if __name__ == "__main__":
    import __main__
    print(__main__.__file__)

    print("syntax ok")
    exit(0)
