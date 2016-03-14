#!/usr/bin/env python3
configs = {
    "server_address": (
        # 你的服务器的地址以及端口
        "example.com", 8964
    ),
    "tunnelc": "tunnelc_simple",
    "tunnelc_simple": {
        "username": "test",
        "password": "test"
    },
    "crypto_module": {
        # 加密模块名
        "name": "aes",
        # 模块初始化参数
        "args": (
            #  fdslight为初始化的aes key值,该值只有在发送验证的时候才使用
            "fdslight",
        )
    },
    # 需要代理的子网范围,在该子网范围内,会进行UDP代理
    "udp_proxy_subnet": ("192.168.1.128", 25),
    # 全局UDP代理,默认为0表示不使用全局,改为1为全局UDP代理,在nat3的网络中你可能需要开启此项
    "global_udp": 0,
    # 不走代理流量的DNS服务器（注意用下一跳的地址,即代理客户端所在路由器地址,不要填公共dns,会出问题)
    "dns": "192.168.1.1",
    # 加密DNS
    "dns_encrypt": "8.8.8.8",
    # DNS绑定地址
    "dns_bind": "0.0.0.0",
    # 访问日志
    "access_log": "/tmp/fdslight_access.log",
    # 故障日志
    "error_log": "/tmp/fdslight_error.log",
}
