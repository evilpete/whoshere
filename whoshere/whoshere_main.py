#!/usr/local/bin/python2.7
"""
    Main calling funtion for whoshere module
"""

from .whoshere import *

def main():

    arpm = ArpMon()

    arpm.parse_args()

    arpm.load_targets()

    setup_io(arpm)

    arpm.run()

    arpm.watch_threads()

    exit(0)

if __name__ == '__main__':

    main()
