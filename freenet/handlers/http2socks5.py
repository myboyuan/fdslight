#!/usr/bin/env python3
"""HTTP协议转换成socks5客户端协议
用以支持一些设备不支持sock5代理的情况
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler


class http2socks5(tcp_handler.tcp_handler):
    pass
