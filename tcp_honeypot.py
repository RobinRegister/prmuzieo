"""TCP-level honeypot — captures raw bytes from JQOneMatrixN RPC connections."""
import socket
import threading
import sqlite3
import time
import json
import sys
import os
import ssl as ssl_mod


def init_db(path):
    db = sqlite3.connect(path, check_same_thread=False)
    db.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT DEFAULT (datetime('now')),
        src_ip TEXT, src_port INTEGER, dst_port INTEGER,
        tls INTEGER DEFAULT 0,
        raw_hex TEXT, raw_text TEXT, raw_len INTEGER
    )''')
    db.commit()
    return db


class TCPHoneypot:
    def __init__(self, port, db_path, use_tls=False, cert_file=None, key_file=None):
        self.port = port
        self.db = init_db(db_path)
        self.use_tls = use_tls
        self.cert_file = cert_file
        self.key_file = key_file

    def handle(self, conn, addr, tls):
        src_ip, src_port = addr[0], addr[1]
        buf = bytearray()
        conn.settimeout(30)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                # Try to respond minimally to keep connection alive
                try:
                    conn.sendall(b'\x00')
                except:
                    break
        except socket.timeout:
            pass
        except Exception as e:
            pass
        finally:
            try:
                conn.close()
            except:
                pass

        if buf:
            raw_hex = buf.hex()[:10000]
            raw_text = buf.decode('utf-8', errors='replace')[:5000]
            self.db.execute(
                'INSERT INTO sessions (src_ip, src_port, dst_port, tls, raw_hex, raw_text, raw_len) VALUES (?,?,?,?,?,?,?)',
                [src_ip, src_port, self.port, 1 if tls else 0, raw_hex, raw_text, len(buf)]
            )
            self.db.commit()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.port))
        sock.listen(50)
        print(f'[+] TCP{"S" if self.use_tls else ""} listening on :{self.port}')

        while True:
            try:
                conn, addr = sock.accept()
                if self.use_tls and self.cert_file and self.key_file:
                    ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(self.cert_file, self.key_file)
                    try:
                        tls_conn = ctx.wrap_socket(conn, server_side=True)
                        threading.Thread(target=self.handle, args=(tls_conn, addr, True), daemon=True).start()
                    except Exception as e:
                        print(f'[-] TLS handshake failed: {e}')
                        conn.close()
                else:
                    threading.Thread(target=self.handle, args=(conn, addr, False), daemon=True).start()
            except Exception as e:
                print(f'[-] Accept error: {e}')
                time.sleep(0.1)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--db', default='tcp.db')
    ap.add_argument('--tls', action='store_true')
    ap.add_argument('--cert', default=None)
    ap.add_argument('--key', default=None)
    args = ap.parse_args()

    hp = TCPHoneypot(args.port, args.db, args.tls, args.cert, args.key)
    hp.run()
