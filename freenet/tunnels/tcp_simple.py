#!/usr/bin/env python3
import freenet.handler.tunnels_tcp_base as tunnels_base
import fdslight_etc.fn_server as fns_config
import freenet.lib.utils as utils

class tunnel(tunnels_base.tunnels_tcp_base):
    __session_ids = None

    def fn_init(self):
        accounts = fns_config.configs["tunnels_simple"]
        for name, passwd in accounts:
            sts = "%s%s" % (name, passwd,)
            md5 = utils.calc_content_md5(sts.encode("utf-8"))
            self.__session_ids[md5] = None
        return

    def fn_recv(self, session_id, pkt_len):
        if session_id not in self.__session_ids:return False
        return True

    def fn_send(self, session_id, pkt_len):
        if session_id not in self.__session_ids:return False
        return True

    def fn_close(self, session_id):
        """处理连接关闭
        :return:
        """
        return

    def fn_timeout(self, session_id):
        """用来处理定时任务"""
        pass
