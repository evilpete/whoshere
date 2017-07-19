#!/usr/bin/python2.7
"""
    whoshere with callbacks for IFTT
    is a example program that can me used to trigger IFTT via webhooks
"""

import requests
from whoshere import ArpMon, setup_io

IFTT_KEY = "XXXXXXXXXXXXXXX-YYYYYY"
IFTT_EVENT = "whoshere"
IFTT_URL = 'https://maker.ifttt.com/trigger/{}/with/key/{}'

_debug = True


def post_data(url, dat, ti=10):
    """
        wrapper for requests.post() to catch exceptions
    """
    try:
        requests.post(url, data=dat, timeout=ti)
    except requests.exceptions.Timeout, re:
        print "Post Error:", re
        raise


def iftt_callback(s, v=None):
    """
        trigger IFTT webhook with status change
    """

    # should never happen
    if v is None:
        if _debug:
            print "iftt_callback: WARNING:", s, v
        return

    report_vals = {
        "value1": v['id'],
        "value2": v['cur_val'],
        "value3": s
    }

    if v['cur_val'] != s:
        if _debug:
            print "iftt_callback:", v['id'], v['cur_val'], "==>", s

        # skip startup alerts
        # if v['cur_val'] != -1:
        #     post_data(v['url'], report_vals)
        post_data(v['url'], report_vals)

        v['cur_val'] = s
    else:
        if _debug:
            print "iftt_callback: SKIP:", v['id'], v['cur_val'], "==>", s


def add_callbacks(am, ifttkey, ifttevent):
    """
        loop through all targets and add a IFTT callback
    """
    if _debug:
        print "add_var_callbacks", am

    xurl = IFTT_URL.format(ifttevent, ifttkey)
    for c in am.mac_targets.values():
        call_val = {
            'url': xurl,
            'id': c.name,
            'cur_val': -1
        }
        c.add_callback(iftt_callback, call_val)


def main():

    arpm = ArpMon()

    arpm.parse_args()

    arpm.load_targets()

    iftt_key = IFTT_KEY
    iftt_event = IFTT_EVENT

    #  check the whoshere config for iftt info
    if arpm.config_parser is not None:
        ini = arpm.config_parser
        if ini.has_section('iftt'):
            if ini.has_option('iftt', 'key'):
                iftt_key = ini.get('iftt', 'key')
            if ini.has_option('iftt', 'event'):
                iftt_event = ini.get('iftt', 'event')


    add_callbacks(arpm, iftt_event, iftt_key)

    setup_io(arpm)

    arpm.run()

    arpm.watch_threads()

    exit(0)

if __name__ == '__main__':

    main()
