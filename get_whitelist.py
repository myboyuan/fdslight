#!/usr/bin/env python3
"""从apnic获取中国IP范围"""
import urllib.request, os

URL = "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
TMP_PATH = "./whitelist.tmp"

# 生成的最终白名单
RESULT_FILE_PATH = "./fdslight_etc/whitelist.txt"


def get_remote_file():
    tmpfile = open(TMP_PATH, "wb")
    response = urllib.request.urlopen(URL)
    rdata = response.read()
    tmpfile.write(rdata)
    tmpfile.close()


def is_ipv4(line):
    """检查是否是IPv4"""
    if line.find("ipv4") < 6: return False
    return True


def is_cn_ipv4(line):
    if line.find("CN") < 6: return False
    return True


def get_subnet(line):
    tmplist = line.split("|")
    if len(tmplist) != 7: return None
    if tmplist[6] != "allocated": return None

    base_net = tmplist[3]
    n = int(tmplist[4]) - 1
    msize = 32 - len(bin(n)) + 2

    return "%s/%s" % (base_net, msize,)


def main():
    print("downloading...")
    get_remote_file()

    print("parsing...")
    fdst = open(TMP_PATH, "r")
    rfdst = open(RESULT_FILE_PATH, "w")

    rfdst.write("# %s\n" % URL)
    rfdst.write("# China IP address\n")

    for line in fdst:
        line = line.replace("\r", "")
        line = line.replace("\n", "")
        if line[0:6] != "apnic|": continue
        if not is_ipv4(line): continue
        if not is_cn_ipv4(line): continue

        subnet = get_subnet(line)
        if not subnet: continue
        sts = "%s\n" % subnet
        rfdst.write(sts)

    print("parse ok")
    rfdst.close()
    fdst.close()
    os.remove(TMP_PATH)


if __name__ == '__main__':
    main()
