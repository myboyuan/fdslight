#!/usr/bin/env python3
configs = {
    "tcp_server_address": (
        # 你的服务器的地址以及端口
        "your_server_address", 8964
    ),
    "tunnelc": "tunnelc_simple",
    "tunnelc_simple": {
        "username": "test",
        "password": "test"
    },
    "tcp_crypto_module": "aes_tcp",
    # 需要代理的子网范围,在该子网范围内,会进行UDP代理
    "proxy_subnet": ("192.168.1.128", 25),
    # 全局UDP代理,默认为0表示不使用全局,改为1为全局UDP代理
    "global_udp": 0,
    # 不走代理流量的DNS服务器
    "dns": "192.168.1.1",
    # DNS绑定地址
    "dns_bind": "0.0.0.0",
    # 访问日志
    "access_log": "/tmp/fdslight_access.log",
    # 故障日志
    "error_log": "/tmp/fdslight_error.log",
}
