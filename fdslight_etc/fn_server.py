#!/usr/bin/env python3
configs = {
    # UDP监听地址
    "udp_listen": (
        "0.0.0.0",
        8964
    ),
    # TCP套接字监听地址
    "tcp_listen": ("0.0.0.0", 1999,),
    # 虚拟局域网IP分配范围
    # 更改了此选项，你需要更改server_nat_script.sh文件，让nat策略与此子网一致
    "subnet": (
        "10.10.10.0",
        24
    ),
    # TCP加密模块
    "tcp_crypto_module": {
        # 加密模块名
        "name": "aes_tcp",
        # 模块初始化参数
        "args": (
            #  fdslight为初始化的aes key值,该值只有在发送验证的时候才使用
            #  建议修改它
            "fdslight",# 此处逗号不能省略
        )
    },
    # udp加密模块
    "udp_crypto_module": {
        "name": "aes_udp",
        "args": (
            #  fdslight为初始化的aes key值,该值只有在发送验证的时候才使用
            #  建议修改它
            "fdslight",# 此处逗号不能省略
        )
    },
    # TCP隧道模块
    "tcp_tunnel": "tcp_simple",
    # UDP隧道模块
    "udp_tunnel": "udp_simple",

    # 自定义的模块配置,该字段非系统定义,是由模块自己定义的
    "tunnels_simple": [
        # 格式为 (用户名,密码,)
        ("test", "test",),
    ],

    # 故障日志
    "error_log": "/tmp/fdslight_error.log",
    # 访问日志
    "access_log": "/tmp/fdslight_access.log",
    # 服务端的DNS代理服务器
    "dns": "8.8.8.8",
    # 最大TCP隧道连接数目
    "max_tcp_conns": 20,
}
