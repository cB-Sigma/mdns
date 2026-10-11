# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# A driver for python-zeroconf (https://github.com/python-zeroconf/
# python-zeroconf, LGPL-2.1), the peer of zeroconf_test.go. It only calls
# python-zeroconf and prints JSON lines:
#
#   zcpeer.py [-out file] browse <type> <wait> [v6|v4]
#   zcpeer.py register <instance> <host> <type> <port> <duration> [v6|v4] [n]
#   zcpeer.py watch <type> <wait> [v6|v4]       added and removed events
import json
import socket
import sys
import time

from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, ServiceStateChange, Zeroconf


out = sys.stdout


def emit(v):
    print(json.dumps(v), file=out, flush=True)


def ipv(arg):
    return {"v6": IPVersion.V6Only, "v4": IPVersion.V4Only}.get(arg, IPVersion.All)


def fqdn(t):
    return t if t.endswith(".local.") else t + ".local."


def own_addresses(version):
    out = []
    for fam in ([socket.AF_INET] if version != IPVersion.V6Only else []) + ([socket.AF_INET6] if version != IPVersion.V4Only else []):
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, fam):
                a = info[4][0].split("%")[0]
                if a not in out and not a.startswith("127.") and a != "::1":
                    out.append(a)
        except OSError:
            pass
    return out


def browse(t, wait, version, events=False):
    zc = Zeroconf(ip_version=version)
    found = {}
    log = []

    def on_change(zeroconf, service_type, name, state_change):
        log.append((state_change, name))

    ServiceBrowser(zc, fqdn(t), handlers=[on_change])
    time.sleep(wait)
    if events:
        for st, name in log:
            emit({"event": "added" if st is ServiceStateChange.Added else "removed" if st is ServiceStateChange.Removed else "updated", "name": name})
        zc.close()
        return
    for st, name in log:
        if st is ServiceStateChange.Removed:
            found.pop(name, None)
            continue
        info = zc.get_service_info(fqdn(t), name, timeout=3000)
        if info is None:
            continue
        inst = name[: -len(fqdn(t)) - 1]
        found[name] = {
            "instance": inst,
            "host": info.server,
            "port": info.port,
            "txt": {k.decode(): (v.decode() if v is not None else "") for k, v in info.properties.items()},
            "ips": info.parsed_addresses(),
        }
    emit(list(found.values()))
    zc.close()


def register(inst, host, t, port, duration, version, n):
    zc = Zeroconf(ip_version=version)
    addrs = [socket.inet_pton(socket.AF_INET6 if ":" in a else socket.AF_INET, a) for a in own_addresses(version)]
    infos = []
    for i in range(n):
        name = inst if n == 1 else f"{inst} {i}"
        info = ServiceInfo(fqdn(t), f"{name}.{fqdn(t)}", addresses=addrs, port=port,
                           properties={"peer": "zeroconf"}, server=f"{host}.local.")
        zc.register_service(info, allow_name_change=True)
        infos.append(info)
        emit({"event": "registered", "instance": info.name[: -len(fqdn(t)) - 1]})
    time.sleep(duration)
    emit({"event": "closing"})
    zc.unregister_all_services()
    zc.close()


def main(argv):
    global out
    if len(argv) > 2 and argv[0] == "-out":
        out = open(argv[1], "w", buffering=1)
        argv = argv[2:]
    cmd = argv[0]
    if cmd == "browse":
        browse(argv[1], float(argv[2]), ipv(argv[3] if len(argv) > 3 else ""))
    elif cmd == "watch":
        browse(argv[1], float(argv[2]), ipv(argv[3] if len(argv) > 3 else ""), events=True)
    elif cmd == "register":
        register(argv[1], argv[2], argv[3], int(argv[4]), float(argv[5]), ipv(argv[6] if len(argv) > 6 else ""),
                 int(argv[7]) if len(argv) > 7 else 1)
    else:
        raise SystemExit("unknown command " + cmd)


if __name__ == "__main__":
    main(sys.argv[1:])
