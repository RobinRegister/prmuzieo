import sqlite3

try:
    db = sqlite3.connect('rpc.db')
    rows = db.execute('SELECT id, ts, src_ip, src_port, dst_port, tls, client_hello_hex, app_data_hex, app_data_text, app_len FROM sessions').fetchall()
    print(f'Total RPC sessions: {len(rows)}')
    for r in rows:
        print(f'  [{r[1]}] {r[2]}:{r[3]} -> :{r[4]} tls={r[5]} app_len={r[9]}')
        if r[6]:
            print(f'    ClientHello HEX ({len(r[6])//2}B): {r[6][:200]}')
        if r[7]:
            h = r[7]
            print(f'    AppData HEX ({len(h)//2}B):')
            for i in range(0, min(len(h), 2000), 100):
                print(f'      {h[i:i+100]}')
        if r[8] and r[8].strip():
            t = ''.join(c if 32 <= ord(c) < 127 else '.' for c in r[8][:500])
            print(f'    AppData TEXT: {t}')
        print()
except Exception as e:
    print(f'Error: {e}')
