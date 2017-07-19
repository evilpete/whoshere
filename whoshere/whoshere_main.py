#!/usr/local/bin/python2.7
"""
    Main calling funtion for whoshere module
"""

import .whoshere

def main():

    arpm = whoshere.ArpMon()

    arpm.parse_args()

    arpm.load_targets()

    whoshere.setup_io(arpm)

    arpm.run()

    arpm.watch_threads()

    exit(0)

if __name__ == '__main__':

    main()
