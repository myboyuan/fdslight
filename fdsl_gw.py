#!/usr/bin/env python3
import sys, os, signal

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_FILE = "/tmp/fdsl_gw.pid"
LOG_FILE = "/tmp/fdsl_gw.log"
ERR_FILE = "/tmp/fdsl_gw_error.log"

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as configfile

import freenet.lib.logging as logging
import freenet.lib.proc as proc
import freenet.lib.gw as gw
import freenet.handlers.gw_netmap as nm_handler
import freenet.handlers.gw_tapdev as tap_handler


class fdsl_gw(dispatcher.dispatcher):
    __configs = None
    __debug = None
    __gw = None

    __netmap_fd = None
    __tap_fd = None

    def init_func(self, debug, configs):
        # netmap 只能使用select事件监听
        self.create_poll(force_select=True)
        self.__configs = configs
        self.__debug = debug

        self.gw_init()

    def check_kern_mod(self):
        ko_file = "%s/netmap/netmap.ko" % BASE_DIR

        if not os.path.isfile(ko_file):
            print("you must install this software")
            return False

        fpath = "%s/fdslight_etc/kern_version" % BASE_DIR
        if not os.path.isfile(fpath):
            print("you must install this software")
            return False

        with open(fpath, "r") as f:
            cp_ver = f.read()
            fp = os.popen("uname -r")
            now_ver = fp.read()
            fp.close()

        if cp_ver != now_ver:
            print("the kernel is changed,please reinstall this software")
            return False

        return True

    def gw_init(self):
        devices = self.__configs["network_devices"]
        lan_address = self.__configs["lan_address"]

        netmap_name = devices["ethernet_name"]
        tap_name = devices.get("tap_name", "gateway")

        if not self.check_kern_mod(): sys.exit(-1)

        cmds = [
            "modprobe -r veth",
            "insmod %s/netmap/netmap.ko" % BASE_DIR,
            "ip link set %s up" % netmap_name,
            # 设置网卡为混杂模式
            "ip link set %s promisc on" % netmap_name,
        ]

        for cmd in cmds: os.system(cmd)

        self.__gw = gw.gw(netmap_name, tap_name, 1024, self.gw_cb)

        self.__netmap_fd = self.create_handler(-1, nm_handler.nm_handler, self.gw.netmap_fd())
        self.__tap_fd = self.create_handler(-1, tap_handler.tapdev_handler, self.gw.tap_fd())

        os.system("ip -4 address replace %s dev %s" % (lan_address["inet"], tap_name,))
        os.system("ip -6 address replace %s dev %s" % (lan_address["inet6"], tap_name,))

    @property
    def debug(self):
        return self.__debug

    @property
    def configs(self):
        return self.__configs

    @property
    def gw(self):
        return self.__gw

    def myloop(self):
        if self.__gw.qos_have_data():
            self.set_default_io_wait_time(0)
            self.__gw.qos_send()
        else:
            self.set_default_io_wait_time(10)

    def gw_cb(self, name: str, ev_name: str, is_added: bool):
        if name not in ("netmap", "tap",): return
        if ev_name not in ("read", "write",): return

        if name == "netmap":
            if is_added:
                if ev_name == "write":
                    self.get_handler(self.__netmap_fd).add_evt_write(self.__netmap_fd)
                else:
                    self.get_handler(self.__netmap_fd).add_evt_read(self.__netmap_fd)
                ''''''
            else:
                if ev_name == "write":
                    self.get_handler(self.__netmap_fd).remove_evt_write(self.__netmap_fd)
                else:
                    self.get_handler(self.__netmap_fd).remove_evt_read(self.__netmap_fd)
                ''''''
            ''''''
        else:
            if is_added:
                if ev_name == "write":
                    self.get_handler(self.__tap_fd).add_evt_write(self.__tap_fd)
                else:
                    self.get_handler(self.__tap_fd).add_evt_read(self.__tap_fd)
                ''''''
            else:
                if ev_name == "write":
                    self.get_handler(self.__tap_fd).remove_evt_write(self.__tap_fd)
                else:
                    self.get_handler(self.__tap_fd).remove_evt_read(self.__tap_fd)
                ''''''
            ''''''
        return

    def release(self):
        self.delete_handler(self.__tap_fd)
        self.delete_handler(self.__netmap_fd)
        del self.__gw

        # 释放调用的内和模块资源之后再删除模块
        os.system("rmmod netmap")


def __start_service(debug):
    if not debug and os.path.isfile(PID_FILE):
        print("the fdsl_gw process exists")
        return

    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

        sys.stdout = open(LOG_FILE, "a+")
        sys.stderr = open(ERR_FILE, "a+")

    configs = configfile.ini_parse_from_file("%s/fdslight_etc/fn_gw.ini" % BASE_DIR)
    cls = fdsl_gw()

    try:
        cls.ioloop(debug, configs)
    except KeyboardInterrupt:
        pass
    except:
        logging.print_error()

    cls.release()
    if not debug: os.remove(PID_FILE)
    sys.exit(0)


def __stop_service():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found fdslight gateway process")
        return

    os.kill(pid, signal.SIGINT)


def main():
    help_doc = """
    debug | start | stop    debug,start or stop application
    """

    if len(sys.argv) != 2:
        print(help_doc)
        return

    d = sys.argv[1]

    if d not in ("debug", "start", "stop",):
        print(help_doc)
        return

    debug = False

    if d == "stop":
        __stop_service()
        return

    if d == "debug": debug = True
    if d == "start": debug = False

    __start_service(debug)


if __name__ == '__main__': main()
