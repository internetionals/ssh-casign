"""Syslog receiver for the audit tests: a Unix datagram socket, UDP and TCP
(newline framed); every message is appended to <dir>/rx-unix, rx-udp, rx-tcp.
Test tool only.
usage: syslog_receiver.py <dir> <port>"""
import os, socket, sys, threading

DIR, PORT = sys.argv[1], int(sys.argv[2])


def append(name, data):
    with open(os.path.join(DIR, name), "ab") as f:
        f.write(data.rstrip(b"\n") + b"\n")


def unix():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(os.path.join(DIR, "log.sock"))
    while True:
        append("rx-unix", s.recv(65536))


def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", PORT))
    while True:
        append("rx-udp", s.recv(65536))


def tcp():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen()
    while True:
        c, _ = s.accept()
        threading.Thread(target=lambda c=c: [append("rx-tcp", l) for l in c.makefile("rb")],
                         daemon=True).start()


for target in (unix, udp, tcp):
    threading.Thread(target=target, daemon=True).start()
threading.Event().wait()
