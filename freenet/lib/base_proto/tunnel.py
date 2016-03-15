#!/usr/bin/env python3
"""协议帧格式
session_id: 2 bytes 会话ID
real_length:2 bytes 实际的数据长度
pkt_id: 2 bytes 包ID
tot_seg: 4 bit 全部的分包个数
seq: 4 bit 当前分包序号
reverse:4 bit 保留
action:4bit 动作
"""

ACT_AUTH = 1
ACT_PING = 2
ACT_PONG = 3
ACT_CLOSE = 4
ACT_DATA = 5

ACTS = (
    ACT_AUTH, ACT_PING, ACT_PONG,
    ACT_CLOSE, ACT_DATA,
)

MIN_FIXED_HEADER_SIZE = 8

# 包建议设置在480到1280之间
EVERY_PKT_SIZE = 1200


class builder(object):
    __session_id = 0
    __fixed_header_size = 0
    __pkt_id = 1

    def __init__(self, fixed_header_size):
        if fixed_header_size < MIN_FIXED_HEADER_SIZE: raise ValueError(
            "the header size can not less than %s" % MIN_FIXED_HEADER_SIZE)
        self.__fixed_header_size = fixed_header_size

    def set_session_id(self, session_id):
        self.__session_id = session_id

    def __build_proto_header(self, real_size, tot_seg, seq, action):
        if action not in ACTS: raise ValueError("not support action type")
        L = (
            (self.__session_id & 0xff00) >> 8, self.__session_id & 0x00ff,
            (real_size & 0xff00) >> 8, real_size & 0x00ff,
            (self.__pkt_id & 0xff00) >> 8, self.__pkt_id & 0x00ff,
            (tot_seg << 4) | seq,
            action,
        )

        if tot_seg == seq:
            if self.__pkt_id == 65535: self.__pkt_id = 0
            self.__pkt_id += 1

        return bytes(L)

    def __calc_tot_seg(self, data_len, max_seg_size):
        """计算数据需要分成多少段"""
        a = int(data_len / max_seg_size)
        if not a: return 1
        b = data_len % max_seg_size
        if not b: return a
        return a + 1

    def build_packets(self, action, data_len, byte_data):
        max_data_size = self.get_max_body_size()
        tot_seg = self.__calc_tot_seg(data_len, max_data_size)
        seq = 1
        b = 0
        e = max_data_size
        data_seq = []

        if data_len == 0:
            base_hdr = self.__build_proto_header(0, 1, 1, action)
            header = self.wrap_header(base_hdr)
            data_seq.append(header)

        while b < data_len:
            data = byte_data[b:e]

            if seq == tot_seg:
                size = len(data)
            else:
                size = max_data_size

            base_hdr = self.__build_proto_header(size, tot_seg, seq, action)

            header = self.wrap_header(base_hdr)
            body = self.wrap_body(size, data)

            data_seq.append(
                b"".join((header, body,))
            )
            seq += 1
            b, e = (e, e + max_data_size,)

        return data_seq

    def wrap_header(self, base_hdr):
        """重写这个方法"""
        pass

    def wrap_body(self, size, body_data):
        """重写这个方法"""
        pass

    def get_max_body_size(self):
        """重写这个这个方法,数据包内容所允许的最大大小"""
        return EVERY_PKT_SIZE - self.__fixed_header_size

    @property
    def fixed_header_size(self):
        return self.__fixed_header_size

    def build_ping(self):
        """
        重写这个方法
        """
        pass

    def build_pong(self):
        """
        重写这个方法
        """
        pass

    def build_close(self):
        """
        重写这个方法
         """
        pass

    def reset(self):
        """
        重写这个方法
        """
        pass


class parser(object):
    __fixed_header_size = 0
    __pkt_id = 0
    # 等待填充的序列号
    __wait_fill_seq = None
    __data_area = None
    # 总共的段数
    __tot_seg = 0

    def __init__(self, fixed_header_size):
        if fixed_header_size < MIN_FIXED_HEADER_SIZE: raise ValueError(
            "the header size can not less than %s" % MIN_FIXED_HEADER_SIZE)

        self.__fixed_header_size = fixed_header_size
        self.__wait_fill_seq = []
        self.__data_area = {}

    def __parse_header(self, header):
        session_id = (header[0] << 8) | header[1]
        real_length = (header[2] << 8) | header[3]
        pkt_id = (header[4] << 8) | header[5]
        seg_info = header[6]

        tot_seg = (seg_info & 0xf0) >> 4
        seq = seg_info & 0x0f

        action = header[7] & 0x0f

        return (session_id, real_length, pkt_id, tot_seg, seq, action,)

    def parse(self, packet):
        real_header = self.unwrap_header(packet[0:self.__fixed_header_size])
        session_id, length, pkt_id, tot_seg, seq, action = self.__parse_header(real_header)
        real_body = self.unwrap_body(length, packet[self.__fixed_header_size:])

        # 丢弃混乱的数据包
        if pkt_id != self.__pkt_id and seq != 1: return None
        # 说明这是第一个数据包

        if seq == 1:
            self.reset()
            self.__pkt_id = pkt_id
            for i in range(tot_seg): self.__wait_fill_seq.append(i + 1)
        self.__data_area[seq] = real_body
        try:
            self.__wait_fill_seq.remove(seq)
        except ValueError:
            pass

        if self.__wait_fill_seq: return None
        # 对数据进行组包
        data_seq = []
        for i in range(tot_seg):
            n = i + 1
            data = self.__data_area.get(n, b"")
            data_seq.append(data)

        return (session_id, action, b"".join(data_seq),)

    def unwrap_header(self, header_data):
        """
        解包头, 重写这个方法
        """
        pass

    def unwrap_body(self, real_size, body_data):
        """
        重写这个方法
        """
        pass

    def reset(self):
        """
        重写这个方法,该reset无需手动调用
        """
        self.__tot_seg = 0
        self.__data_area = {}
        self.__wait_fill_seq = []
