#!/usr/bin/env python3


class base(object):
    """路由基本类,重写这个方法以适合你自己的路由需求"""
    __app = None
    __configs = None
    __bootstrap = None

    def __init__(self, app, bootstrap, configs=None):
        """
        :param app:
        :param bootstrap: 引导handler
        :param configs:
        """
        self.__app = app
        self.__configs = configs
        self.__bootstrap = bootstrap

    @property
    def app(self): return self.__app

    @property
    def bootstrap(self): return self.__bootstrap

    @property
    def configs(self): return self.__configs

    def __call__(self, start_response, environ):
        self.app_call(start_response, environ)

    def app_call(self, start_response, environ):
        """重写这个方法"""
        pass
