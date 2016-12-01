#!/usr/bin/env python3
configs = {
    "udp_server_address": (
        # 你的服务器的地址以及端口
        "example.com", 8964
    ),
    # TCP隧道服务器地址以及端口
    "tcp_server_address": (
        "example.com", 1999
    ),

    # TCP加密模块配置
    "tcp_crypto_module": {
        # 加密模块名
        # 注意,必须和加密模块的文件名字相同
        "name": "aes_tcp",
        # 加密模块配置
        "configs": {
            "key": "fdslight"
        },
    },

    # UDP加密模块配置
    "udp_crypto_module": {
        # 加密模块名
        # 注意,必须和加密模块的文件名字相同
        "name": "aes_udp",
        # 加密模块配置
        "configs": {
            "key": "fdslight"
        }
    },

    # 登录帐户配置
    "account": {
        # 用户名
        "username": "test",
        # 密码
        "password": "test",
    },

    # 隧道类型,可选的值有"tcp","udp","tcp6","udp6",推荐使用udp或者udp6,请根据你的ISP选择适合你的隧道类型
    # tcp6和udp6为ipv6的tcp和udp隧道
    "tunnel_type": "tcp",

    # 是否开启UDP全局代理,一般情况请不要这样做,当你的网络不支持内网穿透的时候,
    # 此项开启时网络一定会支持P2P
    # !!!注意  当为0的时候，白名单内与白名单外的机器无法进行p2p联机
    "udp_global": 0,

    # 强迫一些客户端进行全局UDP代理,如果 udp_global为1，那么这个选项可忽略
    "udp_global_proxy_clients": [
        # "192.168.1.2","192.168.1.3",
    ],

    # 不要进行UDP代理的客户端,此项在udp_global为0时有效
    "udp_no_proxy_clients": [
    ],

    # !!!注意:不走代理流量的DNS服务器,如果DNS无法解析的话建议设置成运行fdslight机器所连的网关的IP地址
    # 否则可能会出现隧道中断而导致需要代理的机器无法上网的情况
    "dns": "223.5.5.5",

    # 本地DNS绑定地址,一般不需要更改
    "dns_bind": "0.0.0.0",

    # 访问日志
    "access_log": "/tmp/fdslight_access.log",
    # 故障日志
    "error_log": "/tmp/fdslight_error.log",
}
