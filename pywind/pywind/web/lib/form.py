#!/usr/bin/env python3
import urllib.parse

"""表单处理"""

### 表单类型
FORM_MULTIPART = 1
FORM_TEXT_PLAIN = 2
FORM_URLENCODED = 3
FORM_UNKOWN = 4


def get_form_type(content_type):
    """获取表单类型"""
    sts = content_type[20:].lstrip()
    return sts[9:]


def get_multipart_boundary(content_type):
    """获取multipart表单的part边界"""
    pos = content_type.find(";")
    if pos < 0:
        sts = content_type.lower()
    else:
        sts = content_type[0:pos].lower()

    if sts == "multipart/form-data":
        return FORM_MULTIPART

    if sts == "application/x-www-form-urlencoded":
        return FORM_URLENCODED

    if sts == "text/plain":
        return FORM_TEXT_PLAIN

    return FORM_UNKOWN


def parse_urlencoded(text):
    return urllib.parse.parse_qs(text)


def parse_text_plain(text):
    return text.replace("+", " ")


def build_urlencoded(key_v):
    """
    :param key_v:{name:[value1,value2,value3,...]}
    :return str:
    """
    seq = []
    for key in key_v:
        for v in key_v[key]:
            sts = "%s=%s" % (key, v)
            seq.append(sts)
        ''''''
    return "&".join(seq)


def build_text_plain(text):
    return text.replace(" ", "+")

