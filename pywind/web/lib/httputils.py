#!/usr/bin/env python3

class Http1xHeaderErr(Exception): pass


def build_http1x_resp_header(status, seq, version="1.1"):
    tmplist = ["HTTP/%s %s\r\n" % (version,status)]
    for k, v in seq:
        sts = "%s: %s\r\n" % (k, v,)
        tmplist.append(sts)
    tmplist.append("\r\n")

    return "".join(tmplist)


def build_http1x_req_header(method, uri, seq):
    tmplist = ["%s %s HTTP/1.1\r\n" % (method, uri,)]
    for k, v in seq: sts = "%s: %s\r\n" % (k, v,)
    tmplist.append("\r\n")

    return "".join(tmplist)


def get_http1x_map(sts):
    """获取HTTP1x的key-value映射值"""
    tmplist = sts.split("\r\n")

    results = []
    tmplist = __drop_nul_seq_elements(tmplist)

    for s in tmplist:
        p = s.find(":")
        if p < 1: raise Http1xHeaderErr("wrong http master:%s" % s)
        name = s[0:p]
        p += 1
        value = s[p:].lstrip()
        results.append((name, value,))

    return results


def __drop_nul_seq_elements(seq):
    new_seq = []

    for s in seq:
        s = s.lstrip()
        if s: new_seq.append(s)

    return new_seq


def parse_htt1x_request_header(sts):
    """解析HTTP1x头"""
    p = sts.find("\r\n")
    first_line = sts[0:p]
    if first_line[0] == " ": raise Http1xHeaderErr("wrong http master:%s" % first_line)
    tmplist = first_line.split(" ")
    tmplist = __drop_nul_seq_elements(tmplist)

    if len(tmplist) != 3: raise Http1xHeaderErr("wrong http master:%s" % first_line)

    t = tuple(tmplist)
    method, uri, version = t
    try:
        n_ver = float(version[5:])
    except ValueError:
        raise Http1xHeaderErr("wrong http version number")

    if n_ver not in (1.0, 1.1,): raise Http1xHeaderErr("not support http version %s" % n_ver)
    p += 2
    return (t, get_http1x_map(sts[p:]),)


def parse_http1x_response_header(sts):
    p = sts.find("\r\n")
    first_line = sts[0:p]
    if p < 4: raise Http1xHeaderErr("wrong http master:%s" % first_line)
    try:
        stcode = int(first_line[0:3])
    except ValueError:
        raise Http1xHeaderErr("wrong http response status:%s" % stcode)

    tmplist = first_line.split(" ")
    tmplist = __drop_nul_seq_elements(tmplist)
    t = tuple(tmplist)

    status, version = t
    try:
        n_ver = float(version[4:])
    except ValueError:
        raise Http1xHeaderErr("wrong http version number")
    if n_ver not in (1.0, 1.1,): raise Http1xHeaderErr("not support http version %s" % n_ver)
    p += 2

    return (t, get_http1x_map(sts[p:]))
