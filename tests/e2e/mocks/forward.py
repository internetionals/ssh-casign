"""A TCP forwarder: 127.0.0.1:<port> to <host>:<port>, so a service whose TLS
certificate names localhost (Lowkey Vault) can be reached by that name.
Test tool only.
usage: forward.py <local port> <host> <port>"""
import socket, sys, threading

LOCAL, HOST, PORT = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])


def pipe(a, b):
    try:
        while data := a.recv(65536):
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", LOCAL))
server.listen()
while True:
    client, _ = server.accept()
    upstream = socket.create_connection((HOST, PORT))
    for a, b in ((client, upstream), (upstream, client)):
        threading.Thread(target=pipe, args=(a, b), daemon=True).start()
