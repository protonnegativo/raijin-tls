"""Local TLS lab for the raijin-tls benchmark: one process, one TLS server per port on 127.0.0.1.

usage: python3 lab.py <certdir> port=kind [port=kind ...]

A kind is <cert>[+<config>]. The cert is a file pair in certdir made by certs.sh (good, app, expired,
self, mismatch, soon, wildcard). The config is the TLS setup:

  modern   TLS 1.2 and 1.3, OpenSSL's default ciphers (the default)
  tls12    TLS 1.2 only
  legacy   TLS 1.0 to 1.3, every cipher OpenSSL has at security level 0 (CBC with SHA-1, no forward
           secrecy, anonymous key exchange)

Every connection that completes the handshake gets a tiny HTTP response and is closed. Only binds to
127.0.0.1; ports must be free.
"""
import os
import socket
import ssl
import sys
import threading

RESPONSE = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nok\n"


def context(certdir, cert, config):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(certdir, cert + ".pem"), os.path.join(certdir, cert + ".key"))
    if config == "modern":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    elif config == "tls12":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif config == "legacy":
        ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    else:
        raise SystemExit(f"unknown config {config}")
    return ctx


def listen(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(128)
    return srv


def serve(srv, ctx):
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn, ctx), daemon=True).start()


def handle(conn, ctx):
    conn.settimeout(5)
    try:
        with ctx.wrap_socket(conn, server_side=True) as s:
            try:
                s.recv(1024)
                s.sendall(RESPONSE)
            except OSError:
                pass
    except (OSError, ssl.SSLError):
        conn.close()


def main():
    certdir = sys.argv[1]
    for spec in sys.argv[2:]:
        port, kind = spec.split("=", 1)
        cert, _, config = kind.partition("+")
        ctx = context(certdir, cert, config or "modern")
        threading.Thread(target=serve, args=(listen(int(port)), ctx), daemon=True).start()
    print("lab up:", " ".join(sys.argv[2:]), flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
