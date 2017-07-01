#!/usr/bin/env python3
"""微信菜单接口
"""
import pywind.web.wechat._access as wechat_access
import json


class MenuErr(Exception): pass


def build_button(name, m_type, key=None, url=None, media_id=None, appid=None, pagepath=None):
    if key and len(key) > 128:
        raise MenuErr("the size of key must be less than 129 bytes")
    if m_type not in ("click", "view", "miniprogram", "media_id", "view_limited"):
        raise MenuErr("the value of type must be click,view or miniprogram")
    if len(name) > 60: raise MenuErr("the size of name must be less than 60")

    if m_type in ("view", "miniprogram",):
        if not url: raise MenuErr("the value of url must be not null")
        if len(url) > 1024: raise MenuErr("the size of url must be less than 1024")

    if m_type in ("view_limited", "media_id",):
        if not media_id: raise MenuErr("the value of media_id must be not null")

    if m_type == "miniprogram" and not appid:
        raise MenuErr("the value of appid must be not null")

    if m_type == "miniprogram" and not pagepath:
        raise MenuErr("the value of pagepath must be not null")

    pydict = {
        "name": name,
        "type": m_type,
    }

    if m_type in ("click",):
        pydict["key"] = key

    if m_type in ("view", "miniprogram",):
        pydict["url"] = url

    if m_type in ("media_id", "view_limited",):
        pydict["media_id"] = media_id

    if m_type == "miniprogram":
        pydict["appid"] = appid

    if m_type == "miniprogram":
        pydict["pagepath"] = pagepath

    return pydict


class wechat_menu(wechat_access.access):
    def request_create_menu(self, menu, access_token):
        sent_data = json.dumps(menu).encode("iso-8859-1")

        self.httpclient.request(
            "POST", path="/cgi-bin/menu/create",
            qs_seq=[("access_token", access_token)],
            headers=[
                ("Content-Length", len(sent_data)),
                ("Content-Type", "application/json"),
            ]
        )

        self.httpclient.send_body(sent_data)

    def create_menu(self, menu=None, access_token=None, async=False):
        """
        :param menu:
        :param access_token:
        :param async:
        :return:
        """
        if not async and (menu == None or access_token == None):
            raise ValueError("the argument menu or access_token must be not null")
        if not async: self.request_create_menu(menu, access_token)

        resp_data = self.get_response_data()
        sts = resp_data.decode("iso-8859-1")

        return json.loads(sts)

    def request_get_menu(self, access_token):
        self.httpclient.request(
            "GET", path="/cgi-bin/menu/get",
            qs_seq=[("access_token", access_token)],
        )

    def get_menu(self, access_token=None):
        if access_token:
            self.request_get_menu(access_token)
        resp_data = self.get_response_data()
        sts = resp_data.decode("iso-8859-1")

        return json.loads(sts)

    def request_del_menu(self, access_token):
        self.httpclient.request(
            "GET", path="/cgi-bin/menu/delete",
            qs_seq=[("access_token", access_token)],
        )

    def del_menu(self, access_token=None):
        if access_token:
            self.request_get_menu(access_token)
        resp_data = self.get_response_data()
        sts = resp_data.decode("iso-8859-1")

        return json.loads(sts)

    def __create_evt_push(self, ToUserName, FromUserName, CreateTime, MsgType, Event, EventKey):
        sts="""<xml>
        <ToUserName><![CDATA[%s]]></ToUserName>
        <FromUserName><![CDATA[%s]]></FromUserName>
        <CreateTime>%s</CreateTime>
        <MsgType><![CDATA[%s]]></MsgType>
        <Event><![CDATA[
        </xml>
        """
        return


cls = wechat_menu("wx3e13a1db5fdf0b7d", "c842a09c8328b2d68ee213c8893fdee8", ssl_on=True)
is_err, result = cls.get_token()

token = result["access_token"]

btn = build_button(
    "Test", "click", key="hello"
)

# print(cls.create_menu({"button": btn}, token))

print(cls.get_menu(token))
