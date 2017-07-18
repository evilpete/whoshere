#!/usr/bin/python2.7
"""
    whoshere with callbacks for
    is a example program that can me used to set State Variables in a ISY standalone home automation controller.
"""

# p ylint: disable=global-statement,protected-access,invalid-name,missing-docstring,broad-except,too-many-branches,no-name-in-module


# import sys
# import os
import argparse
#import io
import json
import time

from whoshere import ArpMon, setup_io, validate_config

import ISY
from ISY.IsyExceptionClass import IsySoapError
# from ISY import IsyVar

__author__ = "Peter Shipley"

verbose = 0
# target_file = None
# config_file = None
ISY_TARG_PATH = "/WEB/CONF/mtargets.jsn"
ISY_CONF_PATH = "/WEB/CONF/whoshere.ini"


def parse_localargs():

    parser = argparse.ArgumentParser(
        epilog="optional ISY args: -a ISY_ADDR -u ISY_USER -p ISY_PASS"
    )

    parser.add_argument("--upload-config", "--upload-conf", dest="upload_config",
                        action='store_true',
                        help="store/upload current config to ISY")

    parser.add_argument("--upload-targets", dest="upload_targets",
                        action='store_true',
                        help="store/upload current target config to ISY")

    args, _ = parser.parse_known_args()

    return vars(args)


def isy_upload_conf(cur_file, isy_path):
    """
            reads config file
            validates data
            uploads to ISY
    """

    # cur_targ_data = None
    print "Config file = {}".format(cur_file)
    print "ISY parh = {}".format(isy_path)
    with open(cur_file) as confd:
        try:
            cur_data = confd.read()
            # target_data = json.loads(cur_data)
        except Exception, err:
            print "json error: ", err
            print cur_data
            print "File not uploaded"
            exit(1)

    if cur_file.endswith(".json"):
        try:
            target_data = json.loads(cur_data)
            validate_config(target_data)
        except Exception, err:
            print "Config Error"
            print err
            exit(1)
        else:
            if verbose:
                print "Config Valid"

    try:
        myisy._sendfile(data=cur_data, filename=isy_path)
    except IsySoapError, se:
        if se.code() == 403:
            print "Error uploading {0} : Forbidden ( code=403 )".format(isy_path)

        raise

    else:
        print "Uploaded filename:", isy_path
        print "Uploaded data:\n", cur_data


def download_conf(config_path=None):
    """
     if specified:
        read config file from command args
     else
        # read from ISY device
    """
    if config_path is None:
        config_path = ISY_TARG_PATH

    conf_data = None
    try:
        conf_data = myisy.soapcomm("GetSysConf", name=config_path)
        if verbose:
            print "Downloaded config_file:", myisy.addr, config_path
        return conf_data
    except ValueError, ve:
        print "Load Error :", ve
        print conf_data
        raise
    except IsySoapError, se:
        if config_path.startswith('/WEB/CONF/'):
            print "Downloaded dat:", conf_data
            print "Config file not found of ISY: addr={} path={}".format(myisy.addr, config_path)
            print "Not IsySoapError :", se
        else:
            print "IsySoapError :", se
        return None


def isy_callback(s, v):
    # pylint: disable=unused-argument
    print "isy_callback", (s, v), v.name

    # 3 h = 10800 sec
#    time_now = int(time.time())
#    if (time_now - last_reload) > 10800:
#        v.isy.load_vars()
#        last_reload = time_now
#        print "isy_callback : load_vars"

    if v.value != s:
        print "isy_callback", v.name, v.value, "==>", s
        v.value = s


def add_var_callbacks(am, isy):

    print "add_var_callbacks", (am, isy)
    print "verbose =", verbose
    for c in am.mac_targets.values():
        var_id = isy._var_get_id(c.name)
        if var_id is not None:
            isy_var = isy.get_var(var_id)
            if am.verbose:
                print "adding callback for", c.name, "var =", var_id, isy_var.status
            c.add_callback(isy_callback, isy_var)


def do_uploads(am):

    if am.verbose:
        print "do_uploads"

    if 'upload_config' in am.args and am.args['upload_config']:
        if 'config_file' in am.args and am.args['config_file']:
            print "isy_upload_conf(", am.target_file, ",", ISY_CONF_PATH, ")"
            # isy_upload_conf(am.config_file, ISY_CONF_PATH)
        else:
            print "Config file must be specified with uploading config data"
        exit(0)

    if 'upload_targets' in am.args and am.args['upload_targets']:
        if 'target_file' in am.args and am.args['target_file']:
            print "isy_upload_conf(", am.target_file, ",", ISY_TARG_PATH, ")"
            # isy_upload_conf(am.target_file, ISY_TARG_PATH)
        else:
            print "Target file must be specified with uploading config data"
        exit(0)

last_reload = 0
if __name__ == '__main__':

    fp = None
    conf_dat = None

    arpmon = ArpMon()

    myisy = ISY.Isy(parsearg=1, eventupdates=0, faststart=1)  # debug=0x223)

    conf_dat = download_conf(ISY_CONF_PATH)
    print "download_conf(ISY_CONF_PATH)", conf_dat
    # if conf_dat is not None:
    #    fp = io.BytesIO(conf_dat)

    arpmon.parse_args(config_dat=conf_dat)

    ag = parse_localargs()
    arpmon.args.update(ag)
    verbose = arpmon.verbose

    targ_dat = download_conf(ISY_TARG_PATH)
    # upload_config = False

    if True:
        print "downloaded targ config :", targ_dat

    if verbose:
        print "arpmon.args :", type(arpmon.args)

    #if ('upload_config' in arpmon.args and arpmon.args['upload_config]) or 'upload_targets' in arpmon.args and arpmon.args['upload_targets']:
    if arpmon.args.get('upload_config') or arpmon.args.get('upload_targets'):
        if verbose:
            print "arpmon.args", arpmon.args
            print "... do upload"
        do_uploads()
        exit(0)

    # preload var info from ISY controller
    myisy.load_vars()
    last_reload = int(time.time())

    arpmon.load_targets(target_dat=targ_dat)

    setup_io(arpmon)

    add_var_callbacks(arpmon, myisy)

    arpmon.run()

    arpmon.watch_threads()

    exit(0)
