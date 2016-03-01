#!/usr/bin/env python3
# fastcgi配置文件样例

import pywind.web.appframework.handler as appHandler
import pywind.web.appframework.middlewares.route as route

configs = {
    "listen": ("127.0.0.1", 9090),
    # 每个进程的最大连接数
    "max_conns": 100,
    # 进程数
    "process": 1,
    "conn_timeout": 60,
    # 故障文件路径
    "error_log": "",
    # WSGI应用
    "application": route.route([(r"^/static/([A-Za-z0-9\-_\.]+)$", appHandler.staticfile, {})])
}
