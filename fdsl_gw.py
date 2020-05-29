#!/usr/bin/env python3
import sys, os

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_FILE = "/tmp/fdsl_gw.pid"
LOG_FILE = "/tmp/fdsl_gw.log"
ERR_FILE = "/tmp/fdsl_gw_error.log"

import pywind.evtframework.evt_dispatcher as dispatcher


class fdsl_gw(dispatcher.dispatcher):
    def init_func(self, *args, **kwargs):
        pass

    def myloop(self):
        pass
