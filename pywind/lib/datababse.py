#!/usr/bin/env python3
class _sql_helper(object):
    # 表前缀
    __data_list = None
    __prefix = ""

    def __init__(self, prefix):
        self.__data_list = []
        self.__prefix = prefix

    def select(self, seq):
        self.__data_list.append(
            "SELECT %s" % ",".join(seq)
        )
        return self

    def where(self, where):
        self.__data_list.append(" WHERE %s" % where)
        return self

    def _from(self, table):
        self.__data_list.append(
            " FROM %s%s" % (self.__prefix, table,)
        )
        return self

    def delete(self):
        self.__data_list.append(
            "DELETE"
        )
        return self

    def insert(self, table, values, fields=None):
        self.__data_list += [
            "INSERT INTO ",
            "%s%s" % (self.__prefix, table),
        ]
        if fields: self.__data_list.append(
            " (%s)" % ",".join(fields)
        )
        self.__data_list.append(
            " VALUES (%s)" % ",".join([str(v) for v in values])
        )

        return self

    def update(self, table, update):
        self.__data_list.append(
            "UPDATE %s%s SET %s" % (self.__prefix, table, update)
        )
        return self

    def get_sql(self):
        tmplist = []
        while 1:
            try:
                tmplist.append(self.__data_list.pop(0))
            except IndexError:
                break
        tmplist.append(";")
        return "".join(tmplist)
        return "".join(tmplist)


class database(object):
    __sql_helper = None
    __connect = None

    def __init__(self, prefix, db_conn):
        self.__connect = db_conn
        self.__sql_helper = _sql_helper(prefix)

    @property
    def sql_helper(self):
        return self.__sql_helper

    def cursor(self):
        return self.__connect.cursor()

    def commit(self):
        self.__connect.commit()

    def rollback(self):
        return self.__connect.rollback()

    def build_value_map(self, field_seq, value_seq):
        """Python默认返回tuple结果,没有包含字段,此函数生成 `字段->值`映射
        """
        length = len(field_seq)
        ret_dict = {}

        for n in range(length):
            field = field_seq[n]
            value = value_seq[n]
            ret_dict[field] = value

        return ret_dict
