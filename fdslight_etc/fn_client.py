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
    # 是否开启UDP全局代理,一般情况请不要这样做,当你的网络不支持内网穿透的时候,请使用此项
    # 此项将会开启P2P的支持
    # 0 表示关闭,1表示开启
    "udp_global": 0,
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
    # 黑名单路由缓存,确保重启之后路由还是成功的
    "route_cache": "/tmp/fdslight_blacklist_route.cache",
}
