#!/usr/bin/env python3
configs = {
    # UDP监听地址
    "udp_listen": ("0.0.0.0", 8964),

    # TCP套接字监听地址
    "tcp_listen": ("0.0.0.0", 1999,),

    # IPV6的UDP监听地址
    "udp6_listen": ("::", 1989),

    # IPV6的TCP监听地址
    "tcp6_listen": ("::", 1991),

    # 是否开启IPv6隧道支持
    "enable_ipv6_tunnel": False,

    # 虚拟局域网IP分配范围
    # 更改了此选项，你需要更改server_nat_script.sh文件，让nat策略与此子网一致
    "subnet": (
        "10.10.10.0",
        24
    ),

    # IPV6版本的虚拟局域网
    # "subnet6":(),

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

    # 连接超时时间
    "timeout": 900,

    # 认证模块,你可以编写自己的认证模块
    # 模块名即为tunnels_auth下的去掉后文件后缀名的名字
    "auth_module": "default",

    # 故障日志
    "error_log": "/tmp/fdslight_error.log",
    # 访问日志
    "access_log": "/tmp/fdslight_access.log",

    # 服务端的DNS代理服务器
    "dns": "8.8.8.8",
    # 最大TCP隧道连接数目
    "max_tcp_conns": 20,

    # 最大DNS并发数目
    "max_dns_request": 2000,
}
