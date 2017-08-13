#!/usr/local/bin/python2.7
"""
    Proof of concept for monitoring network for setting home automation use

    not ready for prime time of any kind

    Example Config file (JSON):

    [
      [ "", "74:75:48:7f:18:27", "is_paperwhite" ],
      [ "", "58:55:ca:92:35:9d", "is_jasper_ipod" ],
      [ "", "60:69:44:11:90:d5", "is_suzanne_ipad" ],
      [ "10.1.1.105", "64:bc:0c:43:6b:a6", "is_home" ],
      [ "10.1.1.131", "e4:58:b8:84:b4:f6", "is_deb_home" ],
      [ "10.1.1.83", "a8:e3:ee:93:3d:c3", "is_ps3_on" ],
      [ "10.1.1.93", "6c:ad:f8:18:1c:33", "is_tv_on" ],
      [ "", "a4:77:33:58:d0:f6", "is_garage_tv_on" ]
    ]

"""

# pylint: disable=global-statement,protected-access,invalid-name,missing-docstring,broad-except,too-many-branches,no-name-in-module

from __future__ import print_function
import io
import select
import sys
import os
import time
import signal
import traceback
import argparse
import json
import logging
# import socket
# import StringIO
import io

from configparser import SafeConfigParser as ConfigParser

from threading import Thread, current_thread
# from BaseHTTPServer import HTTPServer
from http.server import BaseHTTPRequestHandler, HTTPServer


# import scapy.all
from scapy.all import sniff, conf as _scapy_conf, Ether, ARP, IP, Dot3


from .utils import bcast_icmp, bcast_icmp6, upnp_probe
from .webhandler import webHandler
from .mtargets import Mtargets

from .conf import *

# from xmldumper import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

__author__ = "Peter Shipley"

# isy_conf_path = "/WEB/CONF/mtargets.jsn"
# STAT_FILE = "/var/www/whoshere-status"
# WWW_PATH = "/var/www"
# LOG_DIR = "/var/log/whoshere"
# PID_DIR = "/var/run/"
# TIME_AWAY_DEFAULT = 660
# CONFIG_FILE = "whoshere.ini"
# TARGET_FILE = "mtargets.json"
# IFACE = "eth0"  # eth0 em0
# HTTP_PORT_NUMBER = 8088

# VERBOSE = 0

# conf_data = None
_verbose = VERBOSE
_delta = 0
_debug = 0

_scapy_conf.verb = None


# myisy = None
# isy_var = None

_start_time = float(time.time())

# time_away = None
# time_sleep = None
# time_recheck = None
# config_create_var = None
_print_config = None

# time_var_refresh = None
# SNIFF_TIMEOUT = 60 * 16
# TIME_FMT = "%Y-%m-%d %H:%M:%S"
# last_status_change = 0.0



class ArpMon(object):

    time_away_default = TIME_AWAY_DEFAULT
    config_file = CONFIG_FILE
    target_file = TARGET_FILE
    stat_file = STAT_FILE
    log_dir = LOG_DIR
    pid_dir = PID_DIR
    iface = IFACE

    defaults = {
        'time_away': TIME_AWAY_DEFAULT,
        'config_file': CONFIG_FILE,
        'target_file': TARGET_FILE,
        'stat_file': STAT_FILE,
        'log_dir': LOG_DIR,
        'pid_dir': PID_DIR,
        'iface': IFACE,
        # 'http_port': None, # HTTP_PORT_NUMBER,
        'verbose': VERBOSE,
    }

    def __init__(self, **kargs):
        self.mac_targets = {}

        self.kargs = kargs
        self.verbose = VERBOSE

        self.args = {}
        self.args.update(ArpMon.defaults)

        self.sniff_thread = None
        self.ping_thread = None
        self.http_thread = None
        self.http_port = None

        self.last_write = 0
        self.do_stat_write = 0

        self.stat_file = None  # kargs.get('stat_file', ArpMon.stat_file)

        self.config_file = None  # kargs.get('config_file')
        self.config_data = None

        self.target_file = None  # kargs.get('target_file', ArpMon.target_file)
        self.target_data = None
        self.config_parser = None

        self.log_dir = None  # kargs.get('log_dir', ArpMon.log_dir)
        self.pid_dir = None  # kargs.get('pid_dir', ArpMon.pid_dir)
        self.iface = None  # kargs.get('iface', ArpMon.iface)

        self.redirect_io = False

        self.time_away = None  # kargs.get('time_away', ArpMon.time_away_default)
        self.time_sleep = None
        self.time_recheck = None
        # self.time_var_refresh = None
        self.sniff_timeout = None

    def add_target(self, mtarg):
        if isinstance(mtarg, Mtargets):
            self.mac_targets[mtarg.mac] = mtarg
            if _debug:
                print("adding target", mtarg.name)
#            else:
#                print("NOT adding target")

    def print_status_all(self):
        # print("Start Time:", time.strftime(TIME_FMT, time.localtime(_start_time)))
        for c in self.mac_targets.values():
            # print(c.mac, c.ip, c.name, c.is_active, c.last_seen, c.last_change)
            print(time.strftime(TIME_FMT, time.localtime()), \
                    "\t{:<18} {:<10} {:<16} = {:>2}\t{} {}".format(
                        c.mac, (c.ip or "-"), c.name, c.is_active,
                        time.strftime("%H:%M:%S %Y%m%d", time.localtime(c.last_seen)),
                        time.strftime("%H:%M:%S %Y%m%d", time.localtime(c.last_change))
                        ))
        sys.stdout.flush()
        return 0

    def sniff_loop(self):
        verbose_time = int(time.time()) + (self.time_away * 8)
        # last_var_ref = int(time.time())

        pcap_filter = "ether src {}".format(" or ".join(self.mac_targets.keys()))

        if _debug:
            print("pcap_filter=", pcap_filter)

        while True:
            # tcpdump -i em0 -v -v ether src 60:be:b5:ad:28:2d
            try:
                sniff(prn=self._pcap_callback, iface=self.iface,
                      filter=pcap_filter, store=0,
                      timeout=self.sniff_timeout)
            except select.error as se:
                # print("scapy sniff : select.error", se)
                continue

            # time_now = int(time.time())

            if _verbose > 1:
                print(time.strftime(TIME_FMT, time.localtime()), "\tsniff loop timeout")

#            if not self.ping_thread.is_alive():
#                print(time.strftime(TIME_FMT, time.localtime()), "\tping thread died", self.ping_thread)
#                break

            time_now = int(time.time())
            if _verbose or _debug:
                if verbose_time < time_now:
                    verbose_time = time_now + (self.time_away * 8)
                    self.print_status_all()

            # self.write_status_json()
            # self.last_write = time_now

            # sys.stdout.flush()
            # sys.stderr.flush()

        return

    def _pcap_callback(self, pkt):

        eaddr = None
        ipaddr = None
        # pktinfo = None

        if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
            eaddr = pkt[ARP].hwsrc
            ipaddr = pkt[ARP].psrc
        elif IP in pkt:
            eaddr = pkt[Ether].src
            ipaddr = pkt[IP].src
        elif Ether in pkt:
            eaddr = pkt[Ether].src
        elif Dot3 in pkt:
            eaddr = pkt[Dot3].src
        else:
            # pkt.show()
            return None

        if eaddr in self.mac_targets:
            ti = int(time.time())
            time_since = ti - self.mac_targets[eaddr].last_seen

            # dont react to *every* packet in a row
            if (time_since > self.time_recheck * 3) or (self.mac_targets[eaddr].is_active < 1):
                if not self.mac_targets[eaddr].is_active:
                    self.do_stat_write = True
                self.mac_targets[eaddr].set_status(1)
            else:
                self.mac_targets[eaddr].last_seen = ti

            # check if we do not have a IP for his target
            if ipaddr not in [None, "0.0.0.0", "255.255.255.255"]:
                if self.mac_targets[eaddr].ip is None:
                    self.mac_targets[eaddr].ip = ipaddr
                    t = time.strftime(TIME_FMT, time.localtime())
                    if _verbose > 1 or _debug:
                        print("{}\t{} set_ipaddr  {:<16} : {}".format(
                            t, self.mac_targets[eaddr].mac, self.mac_targets[eaddr].name,
                            self.mac_targets[eaddr].ip))

                elif self.mac_targets[eaddr].ip != self.mac_targets[eaddr].ip:
                    self.mac_targets[eaddr].ip = ipaddr
                    t = time.strftime(TIME_FMT, time.localtime())
                    if self.verbose > 1 or _debug:
                        print("{}\t{} new_ipaddr  {:<16} : {} -> {}".format(
                            t, self.mac_targets[eaddr].mac, self.mac_targets[eaddr].name,
                            self.mac_targets[eaddr].ip, ipaddr))

        return None

    def run(self):
        self.start_pingloop()

        if _verbose:
            print(time.strftime(TIME_FMT, time.localtime()), "pre sleep", current_thread().name)
            sys.stdout.flush()

        sys.stdout.flush()

        self.start_sniffloop()

        if isinstance(self.http_port, (int)) and self.http_port > 1:
            self.start_http()

        # self.sniff_loop()

    def start_sniffloop(self):
        self.sniff_thread = Thread(target=self.sniff_loop, name="sniff_looper")
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        if self.verbose > 1:
            print(time.strftime(TIME_FMT, time.localtime()), "\tstart_sniffloop() sniff_thread:", self.sniff_thread.name, current_thread().name)
            # print(time.strftime(TIME_FMT, time.localtime()), "\t", current_thread().name, "sniff loop")

    def start_pingloop(self):

        self.ping_thread = Thread(target=self.ping_loop, name="ping_looper")
        self.ping_thread.daemon = True
        self.ping_thread.start()
        if self.verbose > 1:
            print(time.strftime(TIME_FMT, time.localtime()), \
                     "\tstart_pingloop() ping_thread:", \
                      self.ping_thread.name, current_thread().name)

    def start_http(self):

        webHandler.arp_obj = self

        self.http_thread = Thread(target=self.http_server, name="http_server", args=[self])
        self.http_thread.daemon = True
        self.http_thread.start()
        if self.verbose > 1:
            print(time.strftime(TIME_FMT, time.localtime()), \
                  "\tstart_server() http_server:", \
                  self.http_thread.name, current_thread().name)

    def http_server(self, am):

        # webHandler.arp_obj = self

        server = HTTPServer(('', self.http_port), webHandler)
        if self.verbose:
            print('Started httpserver on port ', self.http_port)
        server.serve_forever()

    def watch_threads(self):

        verbose_print_status_time = int(time.time()) + (self.time_away * 8)

        while True:

            time.sleep(self.time_sleep)
            time_now = int(time.time())

            if self.ping_thread is not None and not self.ping_thread.is_alive():
                print(time.strftime(TIME_FMT, time.localtime()), "\tping thread died", self.ping_thread)
                # self.start_pingloop()
                break

            if self.sniff_thread is not None and not self.sniff_thread.is_alive():
                print(time.strftime(TIME_FMT, time.localtime()), "\tsniff_thread thread died", self.sniff_thread)
                # self.start_sniffloop():
                break

            if self.http_thread is not None and not self.http_thread.is_alive():
                print(time.strftime(TIME_FMT, time.localtime()), "\thttp_thread thread died", self.http_thread)
                # self.start_http()
                break


            if _verbose or _debug:
                if verbose_print_status_time < time_now:
                    verbose_print_status_time = time_now + (self.time_away * 8)
                    self.print_status_all()

            if ((time_now >= (self.last_write + self.sniff_timeout)) or self.do_stat_write):
                if _verbose > 1  or _debug:
                    print(time.strftime(TIME_FMT, time.localtime()), "\twatch_threads :", \
                        (time_now - (self.last_write + self.sniff_timeout)), self.do_stat_write)
                self.write_status_json()
                self.last_write = time_now
                self.do_stat_write = False

    #
    # Send arp and/or pings if we have not heard from the target recently
    #
    def ping_loop(self):
        """
            init stage:
                do a couple broadcasts pings and UPNP probles
                loops though mac_targets and try to arp ping each one

            loop stage:
                sleep for a while

                loop though mac_targets and try to arp ping only one we have not seen in a while

                check for timeout on non-responsive targets and set their state to 0

        """

        time.sleep(5)

        if _verbose > 1:
            print(time.strftime(TIME_FMT, time.localtime()), "\tping_loop init", current_thread().name)
            sys.stdout.flush()

        if _debug:
            print("self pre")

        time_now = float(time.time())  # int(time.time())

        # print_status_all()

        # a couple quick one time broadcasts
        if _verbose > 1:
            print("upnp_probe")
        upnp_probe()
        time.sleep(.30)

        if _verbose > 1:
            print("ping bcast")
        bcast_icmp(self.iface)
        time.sleep(.30)

        if _verbose > 1:
            print("ping6 bcast")
        bcast_icmp6()
        time.sleep(.30)

        if _debug:
            print("ping each")
        for c in self.mac_targets.values():

            if c.last_seen > time_now:
                continue

            if c.ip is None:
                # c.sendicmp()
                # icmp_a, icmp_u = icmp_ping("255.255.255.255", c.mac)
                c.sendip6ping()
            else:
                c.sendarpreq()

            time.sleep(.10)

        if _debug:
            print("post")

        self.print_status_all()

        self.write_status_json()
        self.last_write = int(time_now)
        self.do_stat_write = False

        if _verbose > 1:
            print(time.strftime(TIME_FMT, time.localtime()), "\tping_loop start")

        while True:

            sys.stdout.flush()
            time.sleep(self.time_sleep)

            time_now = float(time.time())  # int(time.time())
            strtm = time.strftime(TIME_FMT, time.localtime())

            for c in self.mac_targets.values():
                time_since = time_now - c.last_seen
                if time_since >= self.time_recheck:
                    if c.ip is None:
                        c.sendip6ping()
                    else:
                        c.sendarpreq()
                    time.sleep(.10)

            for c in self.mac_targets.values():

                if c.is_active == 0:
                    continue

                time_since = time_now - c.last_seen

                if time_since >= self.time_away:
                    if _verbose > 1 and c.ip is None:
                        print("{}\tping_loop: time_since >= time_away, last_seen = {}".format(
                            strtm,
                            time.strftime(TIME_FMT, time.localtime(c.last_seen))))
                        print(strtm, "\t", c.mac, c.ip, c.name)

                    # set inital last_seen to start file of prog
                    # if c.is_active == -1:
                    #    c.last_seen = int(_start_time)

                    c.set_status(0)
                    self.do_stat_write = True

#
# time_sleep  ping_loop sleep time
# time_recheck    = time since last packet before using arping
# time_away       = amount of time before declaring device gone
# time_var_refresh =
# sniff_timeout    = timeout for capy.sniff, mostly used for house cleaning
#


# pcap_filter = "arp and ether src 60:be:b5:ad:28:2d"
# print(time.asctime(time.localtime()))

    def write_status_json(self):
        print("{}\t{} stat_file   {:<16}".format(
            str(time.strftime(TIME_FMT, time.localtime())),
            "xx:xx:xx:xx:xx:xx",
            self.stat_file))
        self.write_status_list_json()

    def generate_status_list(self):

        # print("Start Time:", time.strftime(TIME_FMT, time.localtime(_start_time)))
        ret = []

        time_now = time.time()
        ret.append({
            'name': "status",
            'prog': sys.argv[0],
            'time': time_now,
            'time_str': str(time.strftime(TIME_FMT, time.localtime(time_now))),
            'start_time': _start_time,
            'start_time_str': str(time.strftime(TIME_FMT, time.localtime(_start_time))),
            'pid': os.getpid(),
            'len': len(self.mac_targets),
            'refresh_time': self.sniff_timeout
            })

        # for c in self.mac_targets.values():
        for k in sorted(self.mac_targets.keys()):
            ret.append(self.mac_targets[k].get_dict())

        return ret

    def write_status_list_json(self):

        ddat = self.generate_status_list()

        with open(self.stat_file + '.json', 'w+') as fp:
            # fp.write('"astat":')
            json.dump(ddat, fp, sort_keys=True, indent=2)

        with open(self.stat_file + '.js', 'w+') as fp:
            fp.write('jdata = ')
            json.dump(ddat, fp, sort_keys=True, indent=2)

        return

    def load_status_json(self):
        jdata = None
        jsonfile = self.stat_file + '.json'
        if _verbose:
            print("load_status_json", jsonfile)
        # import pprint
        try:
            if os.path.isfile(jsonfile):
                with io.open(jsonfile, 'r') as fp:
                    if _verbose:
                        print("load_status_json: reading", jsonfile)
                    jdata = json.load(fp, parse_int=int, parse_float=float)
                    if _verbose:
                        print("load_status_json: len", len(jdata))
            # pprint.pprint(jdata)
            return jdata
        except Exception as err:
            traceback = sys.exc_info()[2]
            print("load_status_json err:", err, "\n", traceback)
            raise
        if _verbose:
            print("load_status_json None")
        return None

    def _sig_refresh_statfile(self, cursignal, frame):
        # pylint: disable=unused-argument
        self.write_status_json()

    def _sig_exit_gracefully(self, cursignal, frame):
        # pylint: disable=unused-argument
        """
            Signal handler for clean exits
        """
        if _verbose:
            print("Exiting in a Graceful way\nsig=", cursignal)
        if cursignal not in [signal.SIGINT, signal.SIGTERM, signal.SIGQUIT]:
            traceback.print_exc(file=sys.stdout)

        if _verbose:
            print("Writing Status")
        self.write_status_json()

        if self.pid_dir:
            pidpath = self.pid_dir + "/whoshere.pid"
            if os.path.isfile(pidpath):
                os.remove(pidpath)

        if _verbose:
            print("Flushing")

        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit(0)

    def load_targets(self, target_dat=None):

        if _debug:
            print("run load_targets()")

        if target_dat is None:
            self.target_data = self.get_target_dat()
        else:
            self.target_data = target_dat

        if _verbose > 1:
            print("target_data:", self.target_data)

        if _print_config is not None:
            print(self.target_data)
            exit(0)

        target_list = json.loads(self.target_data)

        # [ "10.1.1.105", "dc:0b:34:b1:cc:5f", "is_home" ]
        # loop through config, skipping errors if possible
        for tp in target_list:
            # check that macaddr is given
            if tp[1] is not None:
                try:
                    mt = self.mac_targets[tp[1]] = Mtargets(mac=tp[1], ip=tp[0], name=tp[2])
                    self.add_target(mt)

                except Exception as err:
                    print("Bad target:", tp, err) # sys.stderr
                    raise

            else:
                print("unknown mac :", tp) # sys.stderr

        #
        # Preload from Json status file
        #
        jd = self.load_status_json()
        if jd is not None:
            # print("jd[0][time] =", (_start_time - jd[0]['time']))
            if (_start_time - jd[0]['time']) < 1200:
                if _verbose:
                    print("PreLoading status_json")
                for d in jd:
                    if 'mac' in d:
                        m = d['mac']
                        if m in self.mac_targets:
                            self.mac_targets[m].last_change = d['last_change']
                            self.mac_targets[m].last_seen = d['last_seen']
                            self.mac_targets[m].is_active = d['stat']
    #       else:
    #           print("Not Loading status_json", (_start_time - jd[0]['time']))
    #    else:
    #       print("no load_status_json()")

        if _verbose > 1:
            # print("Target Macs", " ".join(mac_targets.keys()))
            for c in self.mac_targets.values():
                print("mac_targets = {:<4}: {:<19}{:<5}".format(" ", c.name, c.is_active))

            self.print_status_all()

        sys.stdout.flush()

    def get_target_dat(self, target_file=None):
        """
         if specified:
            read config file from command args
        """
        print("get_target_dat: target_file=", target_file)
        if target_file is None:
            target_file = self.target_file
        print("get_target_dat using target_file=", target_file)
        try:
            if target_file is not None:
                print("Config file = {}".format(target_file))
                with open(target_file) as confd:
                    conf_dat = confd.read()
                print("get_conf: read", target_file)
            print("get_conf: data : ", conf_dat)
            return conf_dat
        except ValueError as ve:
            print("Load Error :", ve)
            print(conf_dat)
            raise

    def get_args(self):

        if _debug:
            print("get_args")

        parser = argparse.ArgumentParser(
            argument_default=argparse.SUPPRESS
            # epilog="optional ISY args: -a ISY_ADDR -u ISY_USER -p ISY_PASS"
        )

        parser.add_argument("--logdir", dest="log_dir",
                            help="Path to log directory")

        parser.add_argument("-t", "--targets", dest="target_file",
                            help="load targets from file")

        parser.add_argument("-c", "--config", dest="config_file",
                            help="load config from file")

        # parser.add_argument("--upload", dest="upload_config",
        #                     action='store_true',
        #                     help="store/upload current config to ISY")

        parser.add_argument("-v", "--verbose", dest="verbose",
                            action='count',
                            help="Turn on verbose debug")

        parser.add_argument("-r", "--redirect-io", dest="redirect_io",
                            action='store_true',
                            # default=redirect_io,
                            help="Redirect_IO to log files")

        parser.add_argument("--time-sleep", dest="time_sleep",
                            type=int,
                            help=argparse.SUPPRESS)
                            # help="pause time for ping_loop"

        parser.add_argument("--time-recheck", dest="time_recheck",
                            type=int,
                            help=argparse.SUPPRESS)
                            # help="wait time before arpping"

        parser.add_argument("--time-away", dest="time_away",
                            type=int,
                            help="away timeout")

        # parser.add_argument("--var-refresh", dest="var_refresh",
        #                     type=int,
        #                     help="ISY var refresh time")

        parser.add_argument("-i", "--interface", dest="iface",
                            # default=None,
                            help="Network Interface")

        parser.add_argument("-P", "--Printconfig", dest="pconf",
                            default=None,
                            action='store_true',
                            help="Print Config and Exit")

        args, _ = parser.parse_known_args()

        return args

    def get_confg(self):
        """
            loads string self.config_data
            else loads file self.config_file
        """

        ini = ConfigParser()
        self.config_parser = ini
        # if isinstance(cfile, (file, StringIO.StringIO, io.BytesIO)):
        if isinstance(self.config_data, str) and self.config_data:
            fp = io.BytesIO(self.config_data)
            ini.readfp(fp)
        elif self.config_file is not None:
            ini.read([self.config_file, os.path.expanduser('~/.' + self.config_file)])

        if ini.has_section('whoshere'):
            return ini.items('whoshere')
        else:
            return {}

    def parse_args(self, config_file=None, config_dat=None):
        """
            load Arge in this priority

                Command line Args
                Config file
                Class Args
                Class Default
        """

        global _verbose
        global _print_config

        if _debug:
            print("parse_args")

        args = self.get_args()

        # print("arg config_file =", config_file)
        # print("arg config_dat =", config_dat)
        # print("ARGS =", args)

        args_v = vars(args)
        # special case for config_file
        # to avoid a chicken or egg problem we parse config location early
        if 'config_file' in args_v:
            self.config_file = args_v['config_file']
            self.config_data = None
        elif config_dat is not None:
            self.config_data = config_dat
        elif config_file is not None:
            self.config_file = config_file
        else:
            self.config_file = ArpMon.defaults['config_file']

        confvalues = self.get_confg()

        self.args.update(ArpMon.defaults)
        self.args.update(self.kargs)
        self.args.update(confvalues)
        self.args.update(args_v)
        merged_args = self.args
        # merged_args.update(confvalues)
        # merged_args.update(vars(args))
        print("\nconfvalues", confvalues)
        print("\nargs", vars(args))
        print("\nmerged_args", merged_args)

        if 'verbose' in merged_args and merged_args['verbose'] is not None:
            self.verbose = int(merged_args['verbose'])
            _verbose = self.verbose

        if 'http_port' in merged_args and merged_args['http_port'] is not None:
            self.http_port = int(merged_args['http_port'])

        if 'stat_file' in merged_args:
            self.stat_file = merged_args['stat_file']

        if 'target_file' in merged_args:
            self.target_file = merged_args['target_file']

        if 'log_dir' in merged_args:
            self.log_dir = merged_args['log_dir']

        if 'pid_dir' in merged_args:
            self.pid_dir = merged_args['pid_dir']

        if 'iface' in merged_args:
            self.iface = merged_args['iface']

        if 'time_away' in merged_args and merged_args['time_away'] is not None:
            self.time_away = int(merged_args['time_away'])

        if 'redirect_io' in merged_args:
            self.redirect_io = bool(merged_args['redirect_io'])

        if 'pconf' in merged_args:
            _print_config = merged_args['pconf']

        if 'time_sleep' in merged_args and merged_args['time_sleep'] is not None:
            self.time_sleep = int(merged_args['time_sleep'])

        if 'time_recheck' in merged_args and merged_args['time_recheck'] is not None:
            self.time_recheck = int(merged_args['time_recheck'])

    #    if upload_config and self.config_file is None:
    #        print("upload option require have config file option")
    #        sys.exit()

        #
        # calc other settings
        #
        if self.time_away is None:
            self.time_away = TIME_AWAY_DEFAULT

        if self.time_sleep is None:
            self.time_sleep = int(self.time_away/3)

        if self.time_recheck is None:
            self.time_recheck = int(self.time_away/2) - 10

        # if self.time_var_refresh is None:
        #     self.time_var_refresh = int(self.time_away * 4) + 10

        if self.sniff_timeout is None:
            self.sniff_timeout = SNIFF_TIMEOUT  # int(self.time_var_refresh / 3) + 10

        Mtargets._verbose = self.verbose

        print("args", type(args))
        print("args pr", args)
        print("vars args", vars(args))
        print("redirect_io", self.redirect_io)
        print("log_dir", self.log_dir)
        print("pid_dir", self.pid_dir)


        # redirect_io=1
        # exit(0)


def sig_ignore(cursignal, frame):
    """
        ignore signal
    """
    print("Ignoring signal :", cursignal, frame) # sys.stderr
    return


# def sig_print_status(cursignal, frame):
#     print(time.strftime(TIME_FMT, time.localtime()), "\tcursignal=", cursignal)
#     print_status_all()


def validate_config(config_dat):
    # pylint: disable=unused-argument
    pass

# def validate_config(config_dat):
#
#    if config_dat is None:
#        raise ValueError("config_data is None")
#
#    if isinstance(config_dat, str):
#        try:
#            # dat = json.loads(conf_data)
#            dat = json.loads(config_dat)
#        except Exception as err:
#            print("json.loads")
#            raise ValueError(str(err))
#    elif isinstance(config_dat, list):
#        dat = config_dat
#
#    for tp in dat:
#        try:
#            ip = tp[0]
#            if ip is not None and len(ip) > 0:
#                socket.inet_aton(ip)
#
#            mac = tp[1]
#            a = re.split('-|:', mac)
#            if len(a) != 6:
#                raise ValueError("invalid mac {}".format(mac))
#            for ia in a:
#                if int(ia, 16) > 255:
#                    raise ValueError("invalid mac {}".format(mac))
#
#            if sum(map(len, a)) != 12:
#                raise ValueError("invalid mac {}".format(mac))
#
#            # will raise exception if var does not exist
#            # myisy.get_var(tp[2])
#
# #       except socket.error as err:
# #           raise ValueError(err + "\n" + str(tp))
#        except Exception as err:
# #            raise ValueError(str(err) + "\n" + str(tp))
#
#    return True


def setup_io(am):

    signal.signal(signal.SIGINT, am._sig_exit_gracefully)
#    signal.signal(signal.SIGTERM, am._sig_exit_gracefully)
#    signal.signal(signal.SIGUSR1, sig_print_status)
#    signal.signal(signal.SIGUSR2, am._sig_refresh_statfile)
    if am.verbose:
        print("init")
        print("setup_io : redirect_io : ", am.redirect_io)
        print("setup_io : log_dir : ", am.log_dir)
        print("setup_io : pid_dir : ", am.pid_dir)

    if am.redirect_io:

        logpath = am.log_dir + "/whoshere.log"
        if os.path.isfile(logpath):
            os.rename(logpath, logpath + '-prev')
#        sys.stdout = open(logpath, 'w+', 0)
        mewout = os.open(logpath, os.O_WRONLY | os.O_CREAT, 0o644)
        sys.stdout.flush()
        os.dup2(mewout, 1)
        os.close(mewout)
        # sys.stdout = os.fdopen(1, 'w')

        logpath = am.log_dir + "/whoshere.err"
        if os.path.isfile(logpath):
            os.rename(logpath, logpath + '-prev')
#        sys.stderr = open(logpath, 'w+', 0)
        mewerr = os.open(logpath, os.O_WRONLY | os.O_CREAT, 0o644)
        sys.stderr.flush()
        os.dup2(mewerr, 2)
        os.close(mewerr)
        # sys.stderr = os.fdopen(2, 'w')

#        sys.stdin = open('/dev/null', 'r')
        devnull = os.open('/dev/null', os.O_RDONLY)
        os.dup2(devnull, 0)
        os.close(devnull)


#       try:
#           os.setpgrp()
#        except Exception as err:
#           print("Error: os.setpgrp(): {}".format(str(err)))

        # signal.signal(signal.SIGHUP, sig_ignore)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

    if am.pid_dir:
        pidpath = am.pid_dir + "/whoshere.pid"
        with open(pidpath, 'w', 0o644) as f:
            f.write("{}\n".format(os.getpid()))

    if am.verbose:
        print("Starting: {}\tpid={}".format(time.strftime(TIME_FMT, time.localtime()), os.getpid()))
        print("time_sleep=\t{:>2}:{:0<2}".format(*divmod(am.time_sleep, 60)))
        print("time_recheck=\t{:>2}:{:0<2}".format(*divmod(am.time_recheck, 60)))
        print("time_away=\t{:>2}:{:0<2}".format(*divmod(am.time_away, 60)))
        # print("var_refresh=\t{:>2}:{:0<2}".format(*divmod(am.time_var_refresh, 60)))
        print("sniff_timeout=\t{:>2}:{:0<2}".format(*divmod(am.sniff_timeout, 60)))
        print("verbose=\t{}".format(_verbose), am.args['verbose'])
        print("delta=\t{}".format(_delta))
        print("pid=\t{}".format(os.getppid()))

        print("config_file", am.config_file)
        sys.stdout.flush()

    return


if __name__ == '__main__':

    if _debug:
        print("__main__")

    arpmon = ArpMon()

    arpmon.parse_args()
    _scapy_conf.verb = None

    arpmon.load_targets()

    setup_io(arpmon)

    arpmon.run()

    arpmon.watch_threads()

    #exit(0)
