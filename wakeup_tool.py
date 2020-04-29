#!/usr/bin/env python3
"""此文件用于唤醒局域网内的机器
"""
import sys, os, json, getopt, socket

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import freenet.lib.wol as wol
import freenet.lib.cfg_check as cfg_check


def get_machines():
    cfg_path = "%s/fdslight_etc/wakeup_machines.json" % BASE_DIR

    if not os.path.isfile(cfg_path):
        sys.stderr.write("not found configure file %s\r\n" % cfg_path)
        return None

    with open(cfg_path) as f:
        s = f.read()
    f.close()
    o = json.loads(s)

    for k, v in o.items():
        rs = wol.mac2byte(v)
        if not rs:
            sys.stderr.write("wrong mac address from name %s\r\n" % k)
            return None

    return o


def wake_up_direct():
    """直接唤醒而不是通过互联网
    :return:
    """
    o = get_machines()
    if None == o: return

    cls = wol.wake_on_lan()
    for k, v in o.items():
        cls.wake(v)
    cls.release()
    print("send wake up ok")


class wake_up_internet(object):
    __s = None
    __key = None
    __hwaddrs = None
    __parser = None
    __builder = None

    def __init__(self, host, port, key, is_ipv6=False):
        self.__key = key
        self.__hwaddrs = []
        self.__parser = wol.parser()
        self.__builder = wol.builder()

        o = get_machines()
        if None == o: return

        for k, v in o.items(): self.__hwaddrs.append(v)

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect((host, port))

        self.__s = s

    def send_request(self):
        packet = self.__builder.build_request(self.__key, hwaddrs=self.__hwaddrs)

        # 多发一些数据包,避免缓冲区问题导致数据不会正常接收到
        # packet = packet * 5

        while 1:
            if not packet: break
            size = self.__s.send(packet)
            packet = packet[size:]

    def recv_request(self):
        while 1:
            recv_data = self.__s.recv(2048)
            self.__parser.input(recv_data)
            while 1:
                try:
                    self.__parser.parse()
                except wol.WOLProtoErr:
                    sys.stderr.write("server error\r\n")
                    return
                rs = self.__parser.get_result()
                if not rs: break
                _t, o = rs
                if _t != wol.TYPE_WAKEUP_RESP:
                    sys.stderr.write("server reponse wrong data frame\r\n")
                    return
                is_error = o
                if not is_error:
                    print("send wake up ok")
                    return
                if 1 == is_error:
                    sys.stderr.write("auth fail\r\n")
                    return

                if is_error != 0:
                    sys.stderr.write("server error\r\n")
                    return
                break

    def wake(self):
        self.send_request()
        self.recv_request()

    def release(self):
        self.__s.close()


def main():
    help_doc = """
    direct                send packet to LAN
    internet              send packet to internet
    
    when is is internet,the argument you must have:
    --key=key
    --host=host 
    --port=port
    """
    if len(sys.argv) < 2:
        print(help_doc)
        return

    _type = sys.argv[1]

    if _type not in ("direct", "internet",):
        print(help_doc)
        return

    if _type == "direct":
        wake_up_direct()
        return

    if len(sys.argv) != 5:
        print(help_doc)
        return

    try:
        opts, args = getopt.getopt(sys.argv[2:], "", ["host=", "port=", "key="])
    except getopt.GetoptError:
        print(help_doc)
        return

    host = None
    port = None
    is_ipv6 = False
    key = "key"

    for k, v in opts:
        if k == "--host": host = v
        if k == "--port": port = v
        if k == "--key": key = v

    if cfg_check.is_ipv6(host): is_ipv6 = True

    if not cfg_check.is_port(port):
        sys.stderr.write("wrong port number %s\r\n" % port)
        return

    if not host or not port:
        print(help_doc)
        return

    port = int(port)

    cls = wake_up_internet(host, port, key, is_ipv6=is_ipv6)
    cls.wake()
    cls.release()


if __name__ == '__main__': main()
