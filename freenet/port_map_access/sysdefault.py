#!/usr/bin/env python3

import freenet.port_map_access._access as access_base
import os


class access(access_base.base):
    def myinit(self):
        path = "%s/../../fdslight_etc/fn_pm_server_rules.json" % os.path.dirname(__file__)

    def change_map_rule(self):
        self.myinit()
