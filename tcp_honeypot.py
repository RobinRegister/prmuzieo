"""TLS-capable TCP honeypot — completes handshake, captures RPC app data, fake MTProto response."""
import socket
import threading
import sqlite3
import time
import ssl as ssl_mod
import os
import struct
import random


def init_db(path):
    db = sqlite3.connect(path, check_same_thread=False)
    db.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT DEFAULT (datetime('now')),
        src_ip TEXT, src_port INTEGER, dst_port INTEGER,
        tls INTEGER DEFAULT 0,
        client_hello_hex TEXT,
        app_data_hex TEXT,
        app_data_text TEXT,
        app_len INTEGER DEFAULT 0
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
        self._lock = threading.Lock()

    def _save(self, src_ip, src_port, tls_flag, client_hello_hex, app_data_hex, app_data_text, app_len):
        with self._lock:
            self.db.execute(
                'INSERT INTO sessions (src_ip, src_port, dst_port, tls, client_hello_hex, app_data_hex, app_data_text, app_len) VALUES (?,?,?,?,?,?,?,?)',
                [src_ip, src_port, self.port, 1 if tls_flag else 0,
                 client_hello_hex, app_data_hex, app_data_text, app_len]
            )
            self.db.commit()

    def handle(self, conn, addr):
        src_ip, src_port = addr[0], addr[1]
        client_hello_hex = ''
        app_data_buf = bytearray()
        tls_conn = None

        try:
            if self.use_tls and self.cert_file and self.key_file:
                # Phase 1: peek at ClientHello before handshake
                conn.settimeout(5)
                try:
                    peek = conn.recv(4096, socket.MSG_PEEK)
                    if peek:
                        client_hello_hex = peek.hex()
                except:
                    pass

                # Phase 2: TLS handshake
                ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(self.cert_file, self.key_file)
                # Allow older TLS versions — the EXE uses TLS 1.2
                ctx.minimum_version = ssl_mod.TLSVersion.TLSv1_2
                ctx.check_hostname = False
                ctx.verify_mode = ssl_mod.CERT_NONE

                tls_conn = ctx.wrap_socket(conn, server_side=True)
                tls_conn.settimeout(30)
                print(f'[+] TLS handshake complete: {src_ip}:{src_port}')

                # Phase 3: read application data
                messages = []
                for _ in range(10):  # up to 10 messages
                    try:
                        chunk = tls_conn.read(65536)
                        if not chunk:
                            break
                        app_data_buf.extend(chunk)
                        print(f'[+] App data chunk {len(chunk)}B from {src_ip}:{src_port}')

                        # Send fake MTProto response to keep client talking
                        # MTProto: auth_key_id(8) + message_id(8) + message_length(4) + payload
                        fake_resp = self._fake_mtproto_response()
                        tls_conn.write(fake_resp)
                        print(f'[+] Sent {len(fake_resp)}B fake MTProto response')

                        messages.append(len(chunk))
                    except ssl_mod.SSLWantReadError:
                        time.sleep(1)
                        continue
                    except (socket.timeout, ssl_mod.SSLWantWriteError,
                            ssl_mod.SSLEOFError, ConnectionError):
                        break

                print(f'[+] Session {src_ip}:{src_port} — {len(messages)} messages, {len(app_data_buf)}B total')
            else:
                # Plain TCP mode (fallback)
                conn.settimeout(30)
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        app_data_buf.extend(chunk)
                except socket.timeout:
                    pass

        except ssl_mod.SSLError as e:
            print(f'[-] TLS error {src_ip}:{src_port}: {e}')
        except Exception as e:
            print(f'[-] Handler error {src_ip}:{src_port}: {e}')
        finally:
            try:
                if tls_conn:
                    tls_conn.close()
                else:
                    conn.close()
            except:
                pass

        # Save everything
        if app_data_buf:
            app_hex = app_data_buf.hex()[:50000]
            app_text = app_data_buf.decode('utf-8', errors='replace')[:10000]
            self._save(src_ip, src_port, self.use_tls,
                      client_hello_hex, app_hex, app_text, len(app_data_buf))

    @staticmethod
    def _fake_mtproto_response():
        """Generate a minimal resPQ-like MTProto response.
        Structure: auth_key_id(8) + message_id(8) + msg_len(4) + constructor(4) + nonce(16) + server_nonce(16) + pq(8) + fingerprints(4*count)
        The client sends req_pq, expects resPQ back. We fake it."""
        auth_key_id = bytes([0] * 8)  # zero auth_key_id
        message_id = struct.pack('<Q', int(time.time() * 1000) % (2**63))
        # resPQ constructor: 0x05162463
        constructor = bytes([0x63, 0x24, 0x16, 0x05])
        nonce = os.urandom(16)
        server_nonce = os.urandom(16)
        pq = bytes([0x17, 0xED, 0x48, 0x94, 0x1A, 0x08, 0xF9, 0x81])  # fake PQ
        fingerprints = struct.pack('<I', 0xC3B42B026CE86B21)  # one fake fingerprint

        payload = constructor + nonce + server_nonce + pq + fingerprints
        msg_len = struct.pack('<I', len(payload))
        return auth_key_id + message_id + msg_len + payload

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.port))
        sock.listen(50)
        label = f'TCP{"+TLS" if self.use_tls else ""}'
        print(f'[+] {label} honeypot on :{self.port}')

        while True:
            try:
                conn, addr = sock.accept()
                print(f'[+] Connection: {addr[0]}:{addr[1]}')
                threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f'[-] Accept: {e}')
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
