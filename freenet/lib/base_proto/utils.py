#!/usr/bin/env python3

import freenet.lib.utils as utils


class ProtoError(Exception): pass


def gen_session_id(user_name, passwd):
    """生成会话ID"""
    sts = "%s%s" % (user_name, passwd)

    return utils.calc_content_md5(sts.encode("utf-8"))
