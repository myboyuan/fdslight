#!/usr/bin/env python3
configs = {
    "bind_address": (
        "0.0.0.0",
        8964
    ),
    # 虚拟局域网IP分配范围
    # 更改了此选项，你需要更改server_nat_script.sh文件，让nat策略与此子网一致
    "subnet": (
        "10.10.10.0",
        24
    ),
    "crypto_module": {
        # 加密模块名
        "name": "aes",
        # 模块初始化参数
        "args": (
            #  fdslight为初始化的aes key值,该值只有在发送验证的时候才使用
            "fdslight",
        )
    },
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
