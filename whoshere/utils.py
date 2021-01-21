from __future__ import print_function    # (at top of module)
import socket
#import time
import struct
import fcntl
import re

import ipaddress
from scapy.sendrecv import send, sendp
# from scapy.layers.l2 import ARP

from scapy.layers.inet import UDP, IP, ICMP, Ether, ARP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
# from scapy.all import send, UDP, IP, ICMP, IPv6, ICMPv6EchoRequest
# from .conf import TIME_FMT

__all__ = ['mac2ipv6', 'get_brdaddr', 'bcast_icmp', 'bcast_icmp6', 'bcast_arp',
           'upnp_probe', 'format_sec', 'normalize_mac']

#TIME_FMT = "%Y-%m-%d %H:%M:%S"


# https://stackoverflow.com/questions/37140846/how-to-convert-ipv6-link-local-address-to-mac-address-in-python
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
    # ipv6 = "fe80::%s/64" % (":".join(ipv6Parts))
    ipv6 = "fe80::%s" % (":".join(ipv6Parts))
    return ipv6

iface_bcast_addr = None
iface_netmask = None
iface_cidr = None

# https://stackoverflow.com/questions/936444/retrieving-network-mask-in-python
def get_brdaddr(ifname):
    """
        Get broadcast for interface
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifname = ifname.encode('utf-8')
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8919, struct.pack('256s', ifname))[20:24])

def get_netmask(ifname):
    """
    Get netmast for interface
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s',ifname))[20:24])

def get_cidr(iface="eth0"):
    """
    Get network CIDR for interface
    """
    global iface_bcast_addr
    global iface_netmask
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if iface_bcast_addr is None:
        iface_bcast_addr = get_brdaddr(iface)

    if iface_netmask is None:
        iface_netmask = get_netmask(iface)
    
    ipnet = ipaddress.IPv4Network(u"/".join([iface_bcast_addr, iface_netmask]), strict=False)
    return(str(ipnet))


def bcast_arp(iface="eth0", cnt=1):
    subnet = get_cidr(iface)
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), iface=iface, count=cnt)
    # arping('10.1.1.*')

def bcast_icmp(iface="eth0", cnt=1):
    """
       Send broadcast IP4 ping
       (Does anyone respond to this anymore?)
    """
    global iface_bcast_addr
    if iface_bcast_addr is None:
        iface_bcast_addr = get_brdaddr(iface)
    payload="whoshere " + iface_bcast_addr + " ff:ff:ff:ff:ff:ff None"
    send(IP(dst=iface_bcast_addr)/ICMP()/payload, iface=iface, count=cnt)


def bcast_icmp6(iface="eth0", cnt=1):
    """
       Send broadcast IP6 ping
    """
    send(IPv6(dst="ff02::1")/ICMPv6EchoRequest()/"whoshere ff02::1 ff:ff:ff:ff:ff:ff None", iface=iface, count=cnt)


def upnp_probe(no_ip6=1, iface="eth0", cnt=1):
    """
        send out a series of UPNP probes (IP4 & IP6)
    """
    # global iface_bcast_addr

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
        probe.format(ST="ssdp:all", IP="239.255.255.250"), iface=iface, count=cnt)
    # time.sleep(.5)
    if not no_ip6:
        send(IPv6(dst="ff02::c") / UDP(sport=1900, dport=1900) / \
            probe.format(ST="ssdp:all", IP="[ff02::c]"), iface=iface, count=cnt)


def format_sec(total_seconds):
    """
        args: seconds
        returns: H:MM:SS
    """
    m, s = divmod(total_seconds, 60)
    h, m = divmod(int(m), 60)
    return "{:d}:{:02d}:{:.2f}".format(h, m, s)

#def ismulticast(ip):
#    """convert dotted quad string to long and check the first octet"""
#    FirstOct = atol(ip) >> 24 & 0xFF
#    return (FirstOct >= 224) and (FirstOct <= 239)

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
