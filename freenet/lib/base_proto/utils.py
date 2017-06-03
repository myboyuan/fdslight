#!/usr/bin/env python3

import hashlib, json

ACT_IPDATA = 1
ACT_DNS = 2

# 表示是TCP SOCKS5代理
ACT_SOCKS5_TCP = 3

# 表示的是UDP SOCKS5代理
ACT_SOCKS5_UDP = 4

ACTS = (
    ACT_IPDATA, ACT_DNS, ACT_SOCKS5_TCP, ACT_SOCKS5_UDP,
)


class ProtoError(Exception): pass


def gen_session_id(user_name, passwd):
    """生成会话ID"""
    sts = "%s%s" % (user_name, passwd)

    return calc_content_md5(sts.encode("utf-8"))


def calc_content_md5(content):
    md5 = hashlib.md5()
    md5.update(content)

    return md5.digest()


def load_crypto_configfile(fpath):
    """载入加密配置文件
    :param fpath:
    :return:
    """
    with open(fpath, "r") as f:
        data = f.read()

    return json.loads(data)
