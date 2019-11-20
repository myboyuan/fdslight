#!/usr/bin/env python3

import sys, os, getopt

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    -t      relay | proxy | all
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return

    for k, v in opts:
        pass
