#!/usr/bin/env python3
### 操作系统代理配置

import os, sys


def windows_config(proxy_host, port, is_ipv6=False):
    """windows 操作系统配置
    :param proxy_host:
    :param port:
    :param is_ipv6:
    :return:
    """
    cmd = "netsh winhttp set proxy %s:%s" % (proxy_host, port,)
    os.system(cmd)


def windows_unconfig():
    cmd = "netsh winhttp reset proxy"
    os.system(cmd)


def osx_config(proxy_host, port, is_ipv6=False):
    """苹果OSX系统配置
    :param proxy_host:
    :param port:
    :param is_ipv6:
    :return:
    """
    pass


def osx_unconfig():
    pass


def os_config(proxy_host, port, is_ipv6=False):
    platform = sys.platform
    if platform.find("darwin") > -1:
        osx_config(proxy_host, port, is_ipv6=is_ipv6)
    if platform.find("win32") > -1:
        windows_config(proxy_host, port, is_ipv6=is_ipv6)


def os_unconfig():
    platform = sys.platform
    if platform.find("darwin") > -1:
        osx_unconfig()
    if platform.find("win32") > -1:
        windows_unconfig()
