#!/usr/bin/env python3
"""计算校检和
"""


def calc_incre_checksum(old_checksum, old_field, new_field):
    """使用增量式计算校检和
    :param old_checksum: 2 bytes的旧校检和
    :param old_field: 2 bytes的旧的需要修改字段
    :param new_field: 2 bytes的新的字段
    :return:
        """
    chksum = (~old_checksum & 0xffff) + (~old_field & 0xffff) + new_field
    chksum = (chksum >> 16) + (chksum & 0xffff)
    chksum += (chksum >> 16)

    return (~chksum) & 0xffff


def calc_checksum(pacekt, size):
    """计算校检和
    :param pacekt:
    :param size:
    :return:
    """
    checksum = 0
    a = 0
    b = 1
    while size > 1:
        checksum += (pacekt[a] << 8) | pacekt[b]
        size -= 2
        a += 2
        b += 2

    if size:
        checksum += pacekt[a]

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)

    return (~checksum) & 0xffff
