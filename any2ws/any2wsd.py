#!/usr/bin/env python3
import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as cfgfile
import sys, os, signal, getopt, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)


def parse_syargv():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:")
    except getopt.GetoptError:
        print(help_doc)
        return None
    d = ""

    for k, v in opts:
        if k == "-d": d = v
    if not d:
        print(help_doc)
        return None

    if d not in ("debug", "start", "stop"):
        print(help_doc)
        return None

    return d


class logging(object):
    __fdst = None

    def __init__(self, path):
        self.__fdst = open(path, "a")

    def write(self, s):
        s1 = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        fmt = "--begin %s\r\n" % s1

        self.__fdst.write(fmt)
        self.__fdst.write(s)
        self.__fdst.write("\r\n")
        self.__fdst.write("--end\r\n")

    def close(self):
        self.__fdst.close()

    def fileno(self):
        return self.__fdst.fileno()

    @property
    def mode(self):
        return self.__fdst.mode

    def tell(self):
        return self.__fdst.tell()

    def writable(self):
        return self.__fdst.writable()

    def seek(self, *args, **kwargs):
        return self.__fdst.seek(*args, **kwargs)

    def flush(self):
        self.__fdst.flush()


class any2wsd(dispatcher.dispatcher):
    def init_func(self):
        self.create_poll()
        self.any2ws_init()

    def any2ws_init(self):
        """初始化函数,重写这个方法
        :return:
        """
        pass

    def any2ws_release(self):
        """释放资源函数,重写这个方法
        :return:
        """
        pass

    @property
    def sysroot(self):
        """获取系统根路径
        :return:
        """
        return BASE_DIR

    def load_configs(self, relative_cfg_path):
        path = "%s/configs/%s" % relative_cfg_path
        pyobj = cfgfile.ini_parse_from_file(path)

        return pyobj
