#!/usr/bin/env python3
import argparse
import socket
import threading
import sqlite3
import time
import ssl
import os
import struct

db_lock = threading.Lock()


def init_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL,
            src_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            tls INTEGER,
            client_hello_hex TEXT,
            app_data_hex TEXT,
            app_data_text TEXT,
            app_len INTEGER
        )
    """)
    conn.commit()
    conn.close()


def store_exchange(db_path, ts, src_ip, src_port, dst_port, tls,
                   client_hello_hex, app_data_hex, app_data_text, app_len):
    with db_lock:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO sessions
            (ts, src_ip, src_port, dst_port, tls, client_hello_hex,
             app_data_hex, app_data_text, app_len)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, src_ip, src_port, dst_port, tls, client_hello_hex,
              app_data_hex, app_data_text, app_len))
        conn.commit()
        conn.close()


def now_ms():
    return int(time.time() * 1000)


def build_http_response(status_line, body, content_type):
    if isinstance(body, str):
        body = body.encode("utf-8")
    headers = (
        "HTTP/1.1 " + status_line + "\r\n" +
        "Content-Type: " + content_type + "\r\n" +
        "Content-Length: " + str(len(body)) + "\r\n" +
        "Connection: keep-alive\r\n" +
        "\r\n"
    ).encode("utf-8")
    return headers + body


def parse_request_line(data):
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return None, None
    first_line = text.split("\r\n", 1)[0]
    parts = first_line.split(" ")
    if len(parts) < 2:
        return None, None
    return parts[0], parts[1]


def handle_get(path):
    # split path and query
    if "?" in path:
        route, _query = path.split("?", 1)
    else:
        route = path

    if route == "/timestamp":
        ts = now_ms()
        body = '{"timestamp":%d,"server_time":%d,"status":"ok"}' % (ts, ts)
        return build_http_response("200 OK", body, "application/json")
    elif route == "/svrs.txt":
        return build_http_response("200 OK", "127.0.0.1", "text/plain")
    else:
        body = '{"status":"ok"}'
        return build_http_response("200 OK", body, "application/json")


def handle_connection(rawconn, addr, ctx, db_path, dst_port, use_tls):
    src_ip, src_port = addr[0], addr[1]
    client_hello_hex = ""
    conn = rawconn

    try:
        if use_tls and ctx is not None:
            # Capture ClientHello before handshake
            try:
                rawconn.settimeout(2)
                peek_data = rawconn.recv(4096, socket.MSG_PEEK)
                if peek_data:
                    client_hello_hex = peek_data.hex()
            except Exception:
                pass

            try:
                conn = ctx.wrap_socket(rawconn, server_side=True)
            except (ssl.SSLError, OSError) as e:
                try:
                    rawconn.close()
                except Exception:
                    pass
                return

        for _ in range(10):
            try:
                conn.settimeout(30)
                data = conn.recv(65536)
            except (socket.timeout, ssl.SSLError, OSError):
                break

            if not data:
                break

            app_data_hex = data.hex()
            app_data_text = data.decode("utf-8", errors="replace")
            app_len = len(data)

            response = b""
            if data.startswith(b"GET "):
                method, path = parse_request_line(data)
                if method == "GET" and path is not None:
                    response = handle_get(path)
                else:
                    response = build_http_response("200 OK", '{"status":"ok"}',
                                                   "application/json")
            else:
                response = build_http_response("200 OK", '{"status":"ok"}',
                                               "application/json")

            # store request exchange
            store_exchange(db_path, time.time(), src_ip, src_port, dst_port,
                           1 if use_tls else 0, client_hello_hex,
                           app_data_hex, app_data_text, app_len)

            try:
                conn.sendall(response)
            except (ssl.SSLError, OSError):
                break

            # store our response exchange
            resp_text = response.decode("utf-8", errors="replace")
            store_exchange(db_path, time.time(), src_ip, src_port, dst_port,
                           1 if use_tls else 0, client_hello_hex,
                           response.hex(), resp_text, len(response))

    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="TCP/TLS HTTP honeypot")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--db", default="honeypot.db")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--cert", default=None)
    parser.add_argument("--key", default=None)
    args = parser.parse_args()

    init_db(args.db)

    ctx = None
    if args.tls:
        if not args.cert or not args.key:
            raise SystemExit("--tls requires --cert and --key")
        if not os.path.exists(args.cert) or not os.path.exists(args.key):
            raise SystemExit("cert or key file not found")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(50)

    print("Honeypot listening on port %d (tls=%s)" % (args.port, args.tls))

    try:
        while True:
            try:
                conn, addr = srv.accept()
            except OSError:
                continue
            t = threading.Thread(
                target=handle_connection,
                args=(conn, addr, ctx, args.db, args.port, args.tls),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("Shutting down")
    finally:
        try:
            srv.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
