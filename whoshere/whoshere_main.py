#!/usr/local/bin/python2.7
"""
    Main calling funtion for whoshere module
"""

from whoshere import *

def main():

    arpmon = ArpMon()

    arpmon.parse_args()

    arpmon.load_targets()

    setup_io(arpmon)

    arpmon.run()

    arpmon.watch_threads()

    exit(0)

if __name__ == '__main__':

    if debug:
        print "__main__"

    main()
