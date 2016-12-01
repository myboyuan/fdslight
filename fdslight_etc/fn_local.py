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

    # DNS服务器,注意不要和本地机器设置的相同
    "dns": "223.6.6.6",

    # Linux机器的DNS配置文件路径
    "dns_resolv": "/etc/resolv.conf",

    # 访问日志
    "access_log": "/tmp/fdslight_access.log",
    # 故障日志
    "error_log": "/tmp/fdslight_error.log",
}
