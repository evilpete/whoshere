import sys
import re
import time


from threading import current_thread
from scapy.all import srp, send, Ether, ARP, IP, ICMP, IPv6, ICMPv6EchoRequest

from .utils import mac2ipv6, format_sec, TIME_FMT

__all__ = ['Mtargets']

#TIME_FMT = "%Y-%m-%d %H:%M:%S"

class Mtargets(object):
    _verbose = 0

    def __init__(self, **kargs):

        self.mac = kargs.get('mac', None)

        # Normalize MAC address
        if self.mac is not None:
            self.mac = ":".join([i.zfill(2) for i in re.split('-|:', self.mac)]).lower()

        self.ip = kargs.get('ip', None)
        if len(self.ip) < 1:
            self.ip = None

        self.name = kargs.get('name', self.mac[:-8])

        # 1262304000 - 2010/1/1
        self.last_change = 0
        self.last_seen = kargs.get('last_seen', 0)
        self.is_active = kargs.get('cur_val', -1)
        # self.set_status_time = 0
        self.linklocal = None

        self.callback = None
        self.callback_args = None

    def add_callback(self, func, *args):
        self.callback = func
        self.callback_args = args

    def set_status(self, state):

        time_now = time.time()
        strtm = time.strftime(TIME_FMT, time.localtime(time_now))

        if self._verbose:  # or (delta and self.is_active != state):

            if self.is_active == -1 and self.last_seen < 1:
                time_since = 0 # time_now - int(_start_time)
                time_change = 0 # time_now - int(_start_time)
            else:
                time_since = time_now - self.last_seen
                time_change = time_now - self.last_change

            if state > 0:
                print "{}\t{} Last_seen   {:<16} :{:>2} {:3.2f} {:<12} : {:3.2f} {:<12}".format(
                    strtm, self.mac, self.name, state,
                    time_since, format_sec(time_since),
                    time_change, format_sec(time_change))

            if self.is_active != state:
                print "{}\t{} set_status  {:<16} :{:>2} ->{:>2} : {:<12} {:3.2f} {:3.2f}".format(
                    strtm, self.mac,
                    self.name,
                    self.is_active, state,
                    current_thread().name,
                    time_since, time_change)

            sys.stdout.flush()

        if state == 1:
            self.last_seen = time_now

        if self.is_active != state:
            self.last_change = int(time_now)
            # print "{}\t{} Set  Change {:<16} : active {} != state {}".format(
            #        strtm, self.mac, self.name,
            #        self.is_active, state)

        self.is_active = state

        if self.callback is not None:
            self.callback(state, *self.callback_args)

        # self.set_status_time = float(time_now)
        sys.stdout.flush()

    def icmp_ping(self):
        if self.ip is None:
            return (None, None)

        if self.mac is None:
            ans, unans = srp(Ether()/IP(dst=self.ip)/ICMP()/"whosthere", timeout=2)
        else:
            ans, unans = srp(Ether(dst=self.mac)/IP(dst=self.ip)/ICMP()/"whosthere", timeout=2)

        if self._verbose > 1:
            print "icmp_ping: ", self.ip, " ans = ", len(ans), ", unans = ", len(unans)
            # sys.stdout.flush()

        return ans, unans

    def arp_ping(self):
        if self.ip is None:
            return (None, None)
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.ip),
                         timeout=1.5, retry=2)
        if self._verbose > 1:
            print "arp_ping: ", self.ip, " ans = ", len(ans), ", unans = ", len(unans)
            # sys.stdout.flush()
        return (ans, unans)
    # http://www.secdev.org/projects/scapy/doc/usage.html

    def sendip6ping(self):
        """
            send a IPv6 Icmp Ping
        """
        if self.mac is not None:
            if self.linklocal is None:
                self.linklocal = mac2ipv6(self.mac)
            if self._verbose > 1:
                print "sendip6ping:", self.linklocal, self.name
            send(IPv6(dst=self.linklocal)/ICMPv6EchoRequest()/"whosthere")

    def sendarpreq(self):
        """
            send a arp request
        """
        if self._verbose > 1:
            print "sendarpreq:", self.ip
        if self.ip is not None:
            send(ARP(op=ARP.who_has, pdst=self.ip))

    def sendicmp(self):
        """
            send a ICMP ping request packet ( IP 4 )
        """
        dst_ip = (self.ip or "255.255.255.255")
        if self._verbose > 1:
            print "sendicmp: ", self.mac, dst_ip
        send(IP(dst=dst_ip)/ICMP()/"whosthere")

    def get_dict(self):
        return {'mac': self.mac,
                'ip': (self.ip or ""),
                'name': self.name,
                'last_change':  int(self.last_change),
                'last_change_str': time.strftime("%H:%M:%S %Y%m%d", time.localtime(self.last_change)),
                'stat': self.is_active,
                'last_seen': self.last_seen,
                'last_seen_str': time.strftime("%H:%M:%S %Y%m%d", time.localtime(self.last_seen))}

    def __str__(self):
        return " ".join([self.mac, (self.ip or "0.0.0.0"), str(self.is_active)])

    def __repr__(self):
        # print "__name__", self.__class__.__name__
        # print "mac", self.mac
        # print "id", id(self)
        # return "<{} [{}] at 0x{:x}>" % (self.__class__.__name__, self.mac, id(self))
        return "<{} [{}] at 0x{:x}>".format(self.__class__.__name__, self.mac, id(self))


#
# Do nothing
# (syntax check)
#
if __name__ == "__main__":
    import __main__
    print __main__.__file__

    print "syntax ok"
    exit(0)
