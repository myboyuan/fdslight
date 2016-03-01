#!/usr/bin/env python3
import re


class Response404(object):
    def __init__(self, start_response):
        start_response("404 Not Found", [("Content-Length", "0")])

    def __iter__(self):
        return self

    def __next__(self):
        raise StopIteration


class route(object):
    __rules = []

    def __init__(self, rules):
        """
        :param application:
        :param rules: [(url_match,object,kwargs)]
        :return:
        """
        if self.__rules:
            return

        for expr, obj, kwargs in rules:
            self.__rules.append(
                (re.compile(expr), obj, kwargs)
            )
        return

    def __match(self, url):
        match_rs = None
        match_cllr = None
        match_kwargs = None

        for cp, obj, kwargs in self.__rules:
            match_rs = cp.findall(url)
            if not match_rs:
                continue
            match_cllr = obj
            match_kwargs = kwargs
            break

        return (match_rs, match_cllr, match_kwargs,)

    def __call__(self, environ, start_resoonse, wsgi_ctl=None):
        path_info = environ.get("PATH_INFO", "/")
        m_rs, m_cllr, m_kwargs = self.__match(path_info)

        if not m_rs:
            m_rs, m_cllr, m_kwargs = self.__match("/404")

        if not m_rs:
            return Response404(start_resoonse)

        cls_instance = m_cllr(environ, start_resoonse, wsgi_ctl, tuple(m_rs), m_kwargs)
        return cls_instance
