import sqlite3
try:
    db = sqlite3.connect('rpc.db')
    rows = db.execute('SELECT * FROM sessions').fetchall()
    print(f'Total RPC sessions: {len(rows)}')
    for r in rows:
        print(f'  [{r[1]}] {r[2]}:{r[3]} -> :{r[4]} tls={r[5]} bytes={r[8]}')
        if r[6]:
            print(f'    HEX: {r[6][:500]}')
        if r[7] and r[7].strip():
            print(f'    TEXT: {r[7][:500]}')
except Exception as e:
    print(f'Error: {e}')
