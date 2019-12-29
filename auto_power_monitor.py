#!/usr/bin/env python3
"""能源监控器
负责观察是否已经断电,如果断电那么发送UDP广播到局域网机器关闭电源
如果来电的话那么发送局域网网卡唤醒让机器自动开机
检查互联网的主机配置文件为 power_monitor.json
注意：该功能是通过网络来观察的,而不是通过读取UPS状态,与互联网连接的设备不要接入UPS,比如路由器
"""

import sys, os, json, getopt, socket, signal, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import freenet.lib.wol as wol
import freenet.lib.cfg_check as cfg_check
import freenet.lib.proc as proc

PID_PATH = "/tmp/auto_power_monitor.pid"


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


def shutdown(port):
    data = bytes([0xff]) * 128

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    s.sendto(data, ("255.255.255.255", port))
    s.close()


class power_monitor(object):
    __power_off_port = None
    __servers = None
    __timeout = 120
    __network_is_ok = None
    __debug = None

    def get_check_servers(self):
        path = "%s/fdslight_etc/power_monitor.json" % BASE_DIR
        servers = []

        if not os.path.isfile(path):
            sys.stderr.write("cannot found configure file %s\r\n" % path)
            return None

        with open(path, "r") as f:
            s = f.read()
        f.close()

        o = json.loads(s)

        for k, v in o.items():
            if not cfg_check.is_port(v):
                sys.stderr.write("the %s is not valid port number\r\n" % k)
                return None
            servers.append(
                (k, int(v),)
            )

        return servers

    def __init__(self, power_off_port, debug=False):
        self.__power_off_port = power_off_port
        self.__network_is_ok = False
        self.__servers = []
        self.__debug = debug

        servers = self.get_check_servers()
        if None == servers:
            os.remove(PID_PATH)
            return
        self.__servers = servers

    def check_network_status(self):
        ok = False

        for host, port in self.__servers:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(3)
                s.connect((host, port,))
            except:
                s.close()
                continue
            s.close()
            ok = True
            break

        return ok

    def send_shutdown(self):
        if self.__debug: print("send shutdown")
        shutdown(self.__power_off_port)

    def wakeup_machine(self):
        o = get_machines()
        if None == o: return

        cls = wol.wake_on_lan()
        for k, v in o.items():
            cls.wake(v)
        cls.release()

    def monitor(self):
        while 1:
            rs = self.check_network_status()

            if rs and self.__debug: print("network OK")
            if not rs and self.__debug: print("network fail")

            # 两次检查网络都无法联通,那么就发送关机信号
            if not rs and not self.__network_is_ok:
                self.send_shutdown()
                continue

            # 如果网络已经联通,且之前的状态也是联通,那么发送唤醒信号
            # 这里需要延迟开机,避免电源又被快速切断导致全部机器开机
            # 这样有可能造成UPS供电不足
            if rs and self.__network_is_ok:
                self.wakeup_machine()

            self.__network_is_ok = rs
            time.sleep(self.__timeout)

    def release(self):
        pass


def stop():
    pid = proc.get_pid(PID_PATH)
    if pid < 0: return
    os.remove(PID_PATH)
    os.kill(pid, signal.SIGINT)


def main():
    help_doc = """
    debug | start | stop | shutdown
    debug | start | shutdown --port=port
    debug:  windows support it
    start   only unix-like support
    stop    only unix-like support
    shutdown will close all hosts
    """

    if len(sys.argv) < 2:
        print(help_doc)
        return

    action = sys.argv[1]

    if action not in ("debug", "stop", "start", "shutdown",):
        print(help_doc)
        return

    if action == "stop":
        stop()
        return

    try:
        opts, args = getopt.getopt(sys.argv[2:], "", ["port="])
    except getopt.GetoptError:
        print(help_doc)
        return

    port = None
    for k, v in opts:
        if k == "--port": port = v

    if None == port:
        print(help_doc)
        return

    if not cfg_check.is_port(port):
        sys.stderr.write("wrong port number\r\n")
        return

    debug = True
    if action == "start":
        debug = False
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)

        pid = os.fork()
        if pid != 0: sys.exit(0)
        proc.write_pid(PID_PATH)

    port = int(port)
    if action == "shutdown":
        print("send shutdown to all host")
        shutdown(port)
        return

    cls = power_monitor(port, debug=debug)
    try:
        cls.monitor()
    except KeyboardInterrupt:
        cls.release()


if __name__ == '__main__': main()
