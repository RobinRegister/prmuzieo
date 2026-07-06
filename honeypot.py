"""JQOneMatrix PoC Honeypot — minimal Windows-compatible, stdlib only."""
import http.server, json, sqlite3, time, sys, os, re
from urllib.parse import urlparse

DB = None

def init_db(path):
    global DB
    DB = sqlite3.connect(path, check_same_thread=False)
    DB.execute('''CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT DEFAULT (datetime('now')), method TEXT, path TEXT,
        headers TEXT, body TEXT, ip TEXT, ua TEXT, flag TEXT)''')
    DB.commit()

def log(method, path, headers, body, ip, flag=''):
    DB.execute('INSERT INTO requests (method,path,headers,body,ip,ua,flag) VALUES (?,?,?,?,?,?,?)',
        [method, path, json.dumps(dict(headers)), body, ip,
         headers.get('User-Agent',''), flag])
    DB.commit()

def has_creds(body):
    return any(k in body.lower() for k in 
        ['api_id','api_hash','api_ident','api_secret','phone','auth_key','token','secret'])

class H(http.server.BaseHTTPRequestHandler):
    def reply(self, code, data, ct='application/json'):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)
    
    def body(self):
        n = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(n).decode('utf-8', errors='replace') if n else '{}'
    
    def route(self, method):
        p = urlparse(self.path).path.rstrip('/') or '/'
        b = self.body()
        ip = self.client_address[0]
        flag = 'CREDENTIAL_CAPTURE' if has_creds(b) else ''
        log(method, p, dict(self.headers), b, ip, flag)
        
        if p in ('/svrs.txt','/ping.txt'):
            return self.reply(200, b'api.jqone.tech\n', 'text/plain; charset=utf-8')
        if p == '/_admin/stats':
            c = DB.execute('SELECT COUNT(*) FROM requests WHERE flag!=""').fetchone()[0]
            t = DB.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
            return self.reply(200, {'total':t,'captures':c})
        if p == '/_admin/creds':
            rows = DB.execute('SELECT * FROM requests WHERE flag!="" ORDER BY id DESC').fetchall()
            cols = ['id','ts','method','path','headers','body','ip','ua','flag']
            return self.reply(200, {'credentials':[dict(zip(cols,r)) for r in rows]})
        if p == '/_admin/clear':
            DB.execute('DELETE FROM requests'); DB.commit()
            return self.reply(200, {'ok':True})
        
        # Generic success response
        r = {'status':'success','server_time':int(time.time())}
        if 'register' in p or 'login' in p:
            r['session_id'] = f'HP-{int(time.time())%9999}'
            r['dc_id'] = 2
        if 'sendCode' in p or 'send_code' in p:
            r['phone_code_hash'] = 'hp-hash'
        if 'verify' in p:
            r['auth_key'] = 'HP-KEY'
        if 'license' in p or 'validate' in p:
            r['valid'] = True
            r['features'] = {'MaxAccounts':9999}
        if 'proxy' in p:
            r['proxies'] = [{'type':'socks5','host':'127.0.0.1','port':10800+i} for i in range(5)]
        if 'server' in p or 'list' in p:
            r['dcs'] = [{'id':i,'ip':'127.0.0.1','port':443} for i in range(1,6)]
        
        self.reply(200, r)
    
    do_GET = lambda s: s.route('GET')
    do_POST = lambda s: s.route('POST')
    do_PUT = lambda s: s.route('PUT')
    do_DELETE = lambda s: s.route('DELETE')
    def log_message(self, *a): pass

if __name__ == '__main__':
    import argparse, ssl
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--db', default='honeypot.db')
    ap.add_argument('--tls-cert', default=None)
    ap.add_argument('--tls-key', default=None)
    a = ap.parse_args()
    init_db(a.db)
    
    srv = http.server.ThreadingHTTPServer(('0.0.0.0', a.port), H)
    
    if a.tls_cert and a.tls_key and os.path.exists(a.tls_cert):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.tls_cert, a.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        print(f'[+] TLS={a.tls_cert}  DB={a.db}  PORT={a.port}')
    else:
        print(f'[+] HTTP  DB={a.db}  PORT={a.port}')
    
    srv.serve_forever()
