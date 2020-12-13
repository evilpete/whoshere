from __future__ import print_function
import sys
import re
import time

from threading import current_thread
from scapy.all import sr, srp, send, sendp, Ether, ARP, IP, ICMP, IPv6, ICMPv6EchoRequest
from scapy.utils6 import  in6_mactoifaceid
from .utils import mac2ipv6, format_sec
from .conf import TIME_FMT, TIME_AWAY_DEFAULT, TIME_AWAY_MAX


__all__ = ['Mtargets']

#TIME_FMT = "%Y-%m-%d %H:%M:%S"

class Mtargets(object):
    _verbose = 0
    _debug_log = 0

    # __slots__ = ['mac', 'name', 'ip', 'last_change', 'last_seen',
    #              'is_active', 'callback', 'callback_args', 'linklocal']

    def __init__(self, **kargs):


        my_mac = kargs.get('mac', None)

        self.mac_type = 'ether'
        # self.mac_type = 'bt'

        # Normalize MAC address
        if my_mac is not None:
            my_mac = my_mac.lower().encode('utf-8')

            if my_mac.startswith('bt:'):
                my_mac = my_mac[3:]
                self.mac_type = 'bt'
            elif my_mac.startswith('mac:'):
                my_mac = my_mac[4:]
                # self.mac_type = 'ether'
            elif my_mac.startswith('ether:'):
                my_mac = my_mac[6:]
                # self.mac_type = 'ether'
            # else:
            #     self.mac_type = 'ether'

            self.mac = ":".join([i.zfill(2) for i in re.split('-|:', my_mac)]).lower().decode('utf-8')
        # else:
        #     self.mac_type = 'ether'

        self.cmd = kargs.get('cmd', None)

        self.ip = kargs.get('ip', None)
        if len(self.ip) < 1:
            self.ip = None

        self.name = kargs.get('name', self.mac[:-8]).decode('utf-8')


        # 1262304000 - 2010/1/1
        self.last_change = 0
        self.prev_change = 0
        self.prev2_change = 0
        self.last_seen = kargs.get('last_seen', 0)
        self.is_active = kargs.get('cur_val', -1)
        # self.set_status_time = 0
        self.linklocal = None

        self.callback = None
        self.callback_args = None

        self.time_away = TIME_AWAY_DEFAULT

        self.ipv6 = kargs.get('ipv6', None)
        self.pkt_type = set()

    def add_callback(self, func, *args):
        # type: (...) -> None
        self.callback = func
        self.callback_args = args

    def set_status(self, state):
        # type: (int) -> None

        time_now = time.time()
        strtm = time.strftime(TIME_FMT, time.localtime(time_now))

        if self.is_active == -1 and self.last_seen < 1:
            time_since = 0 # time_now - int(_start_time)
            time_change = 0 # time_now - int(_start_time)
        else:
            time_since = time_now - self.last_seen
            time_change = time_now - self.last_change

        if self._verbose:  # or (delta and self.is_active != state):

            if state > 0:
                print("{}\t{} Last_seen   {:<20} :{:>2} {:3.2f} {:<12} : {:3.2f} {:<12}".format(
                    strtm, self.mac, self.name, state,
                    time_since, format_sec(time_since),
                    time_change, format_sec(time_change)))

            if self.is_active != state:
                print("{}\t{} set_status  {:<20} :{:>2} ->{:>2} : {:<12} {:3.2f} {:3.2f}".format(
                    strtm, self.mac,
                    self.name,
                    self.is_active, state,
                    current_thread().name,
                    time_since, time_change))

            sys.stdout.flush()

        if state == 1:
            self.last_seen = time_now

        if self.is_active != state:
            self.prev2_change = self.prev_change
            self.prev_change = self.last_change
            self.last_change = int(time_now)
            # print("{}\t{} Set  Change {:<16} : active {} != state {}".format(
            #        strtm, self.mac, self.name,
            #        self.is_active, state))

        # we are changing state from 0 -> 1
        # and we have need state 0 for less then 5 min
        # set add 1min to time_away timeout
        if self.is_active == 0 and state and time_change and time_change < 300:
            if  self.time_away == 0:
                self.time_away = TIME_AWAY_DEFAULT + 60
            else:
                self.time_away = self.time_away + 60

            if self.time_away > TIME_AWAY_MAX:
                self.time_away = TIME_AWAY_MAX

        self.is_active = state

        if self.callback is not None:
            self.callback(state, *self.callback_args)

        # self.set_status_time = float(time_now)
        sys.stdout.flush()


#    def arp_ping(self):
#        if self.ip is None:
#            return (None, None)
#        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.ip),
#                         timeout=1.5, retry=2)
#        if self._verbose > 1:
#            print("arp_ping: ", self.ip, " ans = ", len(ans), ", unans = ", len(unans))
#            # sys.stdout.flush()
#        return (ans, unans)
#    # http://www.secdev.org/projects/scapy/doc/usage.html

    def sendip6ping(self):
        # type: () -> None
        """
            send a IPv6 Icmp Ping
        """
        _addr6 = None
        if self.mac_type != 'ether':
            return

        if self.mac is not None:
            if self.ipv6:
                _addr6 = self.ipv6
            else:
                if self.linklocal is None:
                    self.linklocal = mac2ipv6(self.mac)
                     # in6_mactoifaceid(self.mac)
                _addr6 = self.linklocal

            if self._verbose > 1:
                print("sendip6ping:", _addr6, self.name)
            sendp(Ether(dst=self.mac)/IPv6(dst=_addr6, hlim=0)/ICMPv6EchoRequest()/"whosthere", iface="eth0", count=2)
            ## https://www.packetlevel.ch/html/scapy/scapyipv6.html
            # i = IPv6()
            # i.dst = self.linklocal
            # q = ICMPv6EchoRequest()
            # pkt = (i/q)
            # send(pkt, iface="eth0")
            ## pkt = (Ether(dst=self.mac)/i/q)
            ## sendp(pkt, iface="eth0")

    def sendarpreq(self):
        # type: () -> None
        """
            send a arp request
        """
        if self.mac_type != 'ether':
            return
        if self.ip is None:
            return
        if self._verbose > 1:
            print("sendarpreq:", self.ip, self.name)
        if self.ip is not None:
            send(ARP(op=ARP.who_has, pdst=self.ip), iface="eth0")

    def sendicmp(self):
        # type: () -> None
        """
            send a ICMP ping request packet ( IP 4 )
            do not wait for reply
        """
        # dst_ip = (self.ip or "255.255.255.255")

        if self.mac_type != 'ether':
            return

        if self.ip is None:
            return

        if self._verbose > 1:
            print("sendicmp: ", self.mac, self.ip, self.name)
        sendp(Ether(dst=self.mac)/IP(dst=self.ip)/ICMP()/"whosthere", count=2)

    def icmp_ping(self):
        # type: () -> None
        """
            send a ICMP ping request packet ( IP 4 )
            do wait for reply and report
        """

        if self.mac_type != 'ether':
            return (None, None)

        if self.ip is None:
            return (None, None)

        if self.mac is None:
            ans, unans = sr(IP(dst=self.ip)/ICMP()/"whosthere", timeout=2)
        else:
            ans, unans = srp(Ether(dst=self.mac)/IP(dst=self.ip)/ICMP()/"whosthere", timeout=2)

        if self._verbose > 1:
            print("icmp_ping: ", self.ip, " ans = ", len(ans), ", unans = ", len(unans))
            # sys.stdout.flush()

        return ans, unans

    def get_dict(self):
        return {'mac': self.mac,
                'ip': (self.ip or ""),
                'name': self.name,
                'prev2_change':  int(self.prev2_change),
                'prev2_change_str': time.strftime("%H:%M:%S %Y%m%d", time.localtime(self.prev2_change)),
                'prev_change':  int(self.prev_change),
                'prev_change_str': time.strftime("%H:%M:%S %Y%m%d", time.localtime(self.prev_change)),
                'last_change':  int(self.last_change),
                'last_change_str': time.strftime("%H:%M:%S %Y%m%d", time.localtime(self.last_change)),
                'stat': self.is_active,
                'last_seen': self.last_seen,
                'last_seen_str': time.strftime("%H:%M:%S %Y%m%d", time.localtime(self.last_seen)),
                'time_away' : self.time_away,
                'mac_type' : self.mac_type,
                'ipv6': (self.ipv6 or ""),
                'pkt_type': " ".join(sorted(self.pkt_type)),
               }

    def __str__(self):
        # type: () -> str
        return " ".join([self.mac, (self.ip or self.ipv6 or "0.0.0.0"), str(self.is_active)])

    def __repr__(self):
        # print("__name__", self.__class__.__name__)
        # print("mac", self.mac)
        # print("id", id(self))
        # return "<{} [{}] at 0x{:x}>" % (self.__class__.__name__, self.mac, id(self))
        return "<{} [{}] at 0x{:x}>".format(self.__class__.__name__, self.mac, id(self))


#
# Do nothing
# (syntax check)
#
if __name__ == "__main__":
    import __main__
    print(__main__.__file__)

    print("syntax ok")
    exit(0)
