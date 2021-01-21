#!/usr/bin/python

#!/usr/local/bin/python2.7


# import scapy_ex

from __future__ import print_function

from time import localtime, strftime
# import os
import sys
#import code
import time
import pprint
from .conf import TIME_FMT, TIME_AWAY_DEFAULT, TIME_AWAY_MAX

__all__ = ['scan_wifi_loop']

# import radiotap as r
from scapy.all import *

verbose=0

print(scapy.__file__)


set_seen = set()

wl_targ_list = []

def PacketHandler(pkt):

    if pkt.addr1 == "ff:ff:ff:ff:ff:ff":
        return

    if pkt.addr1 is None or pkt.addr2 is None:
        return

    if pkt.addr2 in wl_targ_list:
        # print(pkt.addr2, "pkt.addr2 spotted", wl_targ_list[pkt.addr2])
        # print("pkt type", pkt.type,  pkt.subtype )
        set_seen.add(pkt.addr2)

#    if verbose:
#        print("\tpkt type", pkt.type,  pkt.subtype )
#        print("\tFCfield\t{:08b} {:08b}".format(fcInt, fDS))
#        print("\tFCfield  :", pkt.FCfield)
#        print("\tSummary  :", pkt.type, ptype,  pkt.summary())
#        print("\tAddr     :", pkt.addr1, pkt.addr2, pkt.addr3, pkt.addr4)

    return



def scan_wifi_loop(mon_obj):

    # Only clients should send Dot11ProbeReq, Dot11AssoReq, and Dot11ReassoReq
    # mtg subtype [assoc-req, probe-req, reassoc-req] 

    # pcap_filter = 'wlan type data'
    # pcap_filter='wlan type mgt and (subtype beacon or subtype probe-req)'
    # subtype probe-req
    #  "addr2 ehost {}".format(" or ".join(sorted(self.mac_targets.keys())))
    # wlan addr2 ehost

    wl_targ_list.extend( mon_obj.mac_targets.keys())

    if mon_obj is None:
        print("Wifi mon obj is None")
        return

    if mon_obj.wifi_mondev is None:
        print("Wifi mondev is None")
        return

    if mon_obj.verbose:
        print(__name__, "Wifi device is", mon_obj.wifi_mondev)
        sys.stdout.flush()

   # pcap_filter = '(wlan type data) or (wlan type mgt and (subtype assoc-req  or subtype probe-req or subtype reassoc-req))'
    pcap_filter = "wlan addr2 {}".format(" or ".join(sorted(mon_obj.mac_targets.keys())))

    try:
        while True:

            for chan in [1, 6, 11]:

                if mon_obj.verbose > 2:
                    print("Channel", chan)
                    sys.stdout.flush()
                subprocess.call(['iwconfig', mon_obj.wifi_mondev, 'channel', str(chan)])

                if mon_obj.verbose > 2:
                    print('sniffing Wifi...')
                    print('iface=', mon_obj.wifi_mondev)
                    sys.stdout.flush()
                #timeout = 12000
                sniff(iface=mon_obj.wifi_mondev, prn=PacketHandler, filter=pcap_filter, store=0, timeout=20, count=300)

                if mon_obj.verbose and set_seen:
                    time_now = time.time()
                    print("{}\tWifi chan {} eaddr {}".format(
                        time.strftime(TIME_FMT, time.localtime(time_now)),
                        chan,
                        str(sorted(list(set_seen)))))
                    sys.stdout.flush()

                for eaddr in set_seen:

                    if eaddr in mon_obj.mac_targets:
                        ti = int(time.time())

                        mtarg = mon_obj.mac_targets[eaddr]

                        mtarg.pkt_type.add('Wifi')

                        if mtarg.is_active == 0:
                            mtarg.set_status(1)
                        else:
                            if mtarg.last_seen < ti:
                                mtarg.last_seen = ti

                set_seen.clear()

                # print('sleeping 8...')
                time.sleep(180)
                # time.sleep(mon_obj.time_sleep)


    # except KeyboardInterrupt:
    #    print 'Keyboard Interrupt Exception'
    #    print 'Saving Data....'
    #    sys.stdout.flush()
    #    sys.stderr.flush()

    except Exception as _e:
        print("Exception: ", _e)


