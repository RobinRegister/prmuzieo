import sqlite3, glob, json, sys

for f in sorted(glob.glob('rpc_*.db')):
    db = sqlite3.connect(f)
    rows = db.execute('SELECT * FROM sessions').fetchall()
    print(f'{f}: {len(rows)} sessions')
    for r in rows:
        print(f'  [{r[1]}] {r[2]}:{r[3]} -> :{r[4]} tls={r[5]} len={r[8]}')
        if r[6]:
            print(f'    HEX: {r[6][:200]}')
        if r[7] and r[7].strip():
            print(f'    TEXT: {r[7][:300]}')
        print()
