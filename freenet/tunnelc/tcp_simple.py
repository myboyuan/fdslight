#!/usr/bin/env python3

import freenet.handler.tunnelc_tcp_base as tunnelc_base
import fdslight_etc.fn_client as fnc_config
import freenet.lib.base_proto.utils as proto_utils

class tunnel(tunnelc_base.tunnelc_tcp_base):

    def fn_get_session_id(self):
        auth_info = fnc_config.configs["tunnelc_simple"]
        username = auth_info["username"]
        password = auth_info["password"]

        sts = "%s%s" % (username, password)

        return proto_utils.calc_content_md5(sts.encode("iso-8859-1"))
