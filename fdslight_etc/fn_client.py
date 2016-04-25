#!/usr/bin/env python3
configs = {
    "udp_server_address": (
        # 你的服务器的地址以及端口
        "example.com", 1999
    ),
    # TCP隧道服务器地址以及端口
    "tcp_server_address": (
        "example.com", 8964
    ),
    # 使用的TCP隧道模块
    "tcp_tunnel": "tcp_simple",
    # 使用的UDP隧道模块
    "udp_tunnel": "udp_simple",

    # 该字段是模块内部定义的，用于自定义模块的配置
    "tunnelc_simple": {
        "username": "test",
        "password": "test"
    },

    "tcp_crypto_module": {
        "name": "aes_tcp",
        "args": (
            "fdslight",  # 此处逗号不能省略
        ),
    },

    "udp_crypto_module": {
        # 加密模块名
        "name": "aes_udp",
        # 模块初始化参数
        "args": (
            #  fdslight为初始化的aes key值,该值只有在发送验证的时候才使用
            "fdslight",  # 此处逗号不能省略
        )
    },
    # 隧道类型,可选的值有"tcp","udp",推荐使用udp,请根据你的ISP选择适合你的隧道类型
    "tunnel_type": "udp",
    # 是否开启UDP全局代理,一般情况请不要这样做,当你的网络不支持内网穿透的时候,请使用此项
    # 此项开启时网络一定会支持P2P
    "udp_global": 0,
    # 不走代理流量的DNS服务器
    "dns": "223.5.5.5",
    # DNS绑定地址
    "dns_bind": "0.0.0.0",
    # 访问日志
    "access_log": "/tmp/fdslight_access.log",
    # 故障日志
    "error_log": "/tmp/fdslight_error.log",
    # 黑名单路由缓存,确保重启之后路由还是成功的
    "route_cache": "/tmp/fdslight_blacklist_route.cache",
}
