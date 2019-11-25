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
    pass


def windows_unconfig():
    pass


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
    if platform == "darwin":
        osx_config(proxy_host, port, is_ipv6=is_ipv6)
    if platform == "win32":
        windows_config(proxy_host, port, is_ipv6=is_ipv6)


def os_unconfig():
    platform = sys.platform
    if platform == "darwin":
        osx_unconfig()
    if platform == "win32":
        windows_unconfig()
