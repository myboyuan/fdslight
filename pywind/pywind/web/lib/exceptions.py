#!/usr/bin/env python3

class RequestHeaderTooLongErr(Exception):
    """
    协议头太长
    """
    pass


class HttpProtoErr(Exception):
    """
    HTTP协议故障
    """
    pass


class NotSupportUpgradeProtoErr(Exception):
    """不支持的升级协议"""
    pass


class WebAppError(object):
    pass
