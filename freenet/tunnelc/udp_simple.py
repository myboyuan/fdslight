#!/usr/bin/env python3

import fdslight_etc.fn_client as fnc_config
import freenet.handler.tunnelc_udp_base as tunnelc_base
import freenet.lib.base_proto.utils as proto_utils


class tunnel(tunnelc_base.tunnelc_udp_base):
    def fn_get_session_id(self):
        user = fnc_config.configs["tunnelc_simple"]["username"]
        passwd = fnc_config.configs["tunnelc_simple"]["password"]

        sts = "%s%s" % (user, passwd,)

        return proto_utils.calc_content_md5(sts.encode("iso-8859-1"))
