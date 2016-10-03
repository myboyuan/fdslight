#!/usr/bin/env python3


class base(object):
    """路由基本类,重写这个方法以适合你自己的路由需求"""
    def __call__(self, environ, start_response):
        return self.app_call(environ, start_response)

    def app_call(self, environ, start_response):
        """重写这个方法"""
        pass
