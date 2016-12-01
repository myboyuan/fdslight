#!/usr/bin/env python3
import sys, os, getopt
import _fdsl

d = os.path.dirname(sys.argv[0])
sys.path.append(d)


def main():
    help_doc = """
    -u blacklist                update blacklist
    -m gateway | server | local gateway,server or local
    -d stop | start | debug     stop,start,debug
    -h                          print help
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:")
    except getopt.GetoptError:
        print(help_doc)
        return
    m = ""
    d = ""
    u = ""

    size = len(opts)

    for k, v in opts:
        if k == "-d":
            d = v
        if k == "-m":
            m = v
        if k == "-u":
            u = v
        if k == "-h":
            print(help_doc)
            return
        continue

    if u not in ("blacklist", "whitelist",) and u != "":
        print(help_doc)
        return

    if u and size != 1:
        print(help_doc)
        return

    if u == "blacklist" and size == 1:
        _fdsl.update_blacklist()
        return

    if not m or not d:
        print(help_doc)
        return

    if d not in ["stop", "start", "debug"]:
        print(help_doc)
        return

    if m not in ["gateway", "server", "local"]:
        print(help_doc)
        return

    if d == "stop":
        _fdsl.stop_service()
        return

    debug = False
    if d == "debug": debug = True

    if m == "server":
        import _fdsl_server
        fdslight_ins = _fdsl_server.fdslightd()
    elif m == "gateway":
        import _fdsl_gw
        fdslight_ins = _fdsl_gw.fdslightgw()
    else:
        import _fdsl_local
        fdslight_ins = _fdsl_local.fdslightlc()

    try:
        fdslight_ins.ioloop(m, debug=debug)
    except KeyboardInterrupt:
        _fdsl.clear_pid_file()
        sys.stdout.flush()
        sys.stdout.close()
        sys.stderr.close()

    return


if __name__ == '__main__': main()
