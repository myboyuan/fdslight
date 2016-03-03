#!/usr/bin/env python3
configs = {
    "tcp_bind_address": (
        "0.0.0.0",
        8964
    ),
    # 虚拟局域网IP分配范围
    "subnet": (
        "10.10.10.0",
        24
    ),
    # DNS代理服务器
    "dns": "8.8.8.8",
    # TCP加密模块
    "tcp_crypto_module": "aes_tcp",
    # 隧道模块
    "tunnels": "tunnels_simple",
    # 隧道模块配置
    "tunnels_simple": [
        # 格式为 (用户名,密码,)
        ("test", "test",),
    ],
    # 故障日志
    "error_log": "/tmp/fdslight_error.log",
    # 访问日志
    "access_log": "/tmp/fdslight_access.log",
}
