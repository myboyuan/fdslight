#!/usr/bin/env python3
"""应用层代理协议,该协议加载在隧道协议之上
1.建立连接
    客户端请求如下报文:
        cookie_id:8bytes 客户端生成的cookie id
        atyp:地址类型,同socks5 atyp
        addr_len: 1 byte地址长度
        port:2 bytes 客户端请求端口,如果为UDP代理那么该项可忽略
        address:请求地址,如果为UDP代理那么该项可忽略
    服务端响应如下:
        cookie_id:8 bytes 客户端给定的cookie id
        resp_code:1 byte 响应状态码,1表示成功,0表示失败

2.发送数据(客户端和服务端)
    TCP协议如下:
        cookie_id:8 bytes
        data:
    UDP协议如下
        cookie_id:8 bytes
        addr_len:1 byte地址长度
        port:2 bytes 端口
        data:数据内容
"""
