#!/usr/bin/env python3
"""SQLite reference for exact bridge ordinal and numeric-constant boundary queries."""
import json
from pathlib import Path
import sqlite3

HERE=Path(__file__).resolve().parent
CASES=[('max','2147483647'),('above','2147483648'),('negmax','-2147483647'),
       ('negmin','-2147483648'),('posabove','+2147483648'),('real','1.0')]
EXPRESSIONS=tuple(expr for _,expr in CASES)


def build_statement(op, expr):
    """Compose a statement from this file's frozen case table only."""
    if expr not in EXPRESSIONS:
        raise RuntimeError('expression outside the frozen case table: '+repr(expr))
    if op=='order':
        return 'SELECT k FROM facts WHERE k IS NOT NULL ORDER BY '+expr
    if op=='group':
        return 'SELECT COUNT(*) AS n FROM facts WHERE k IS NOT NULL GROUP BY '+expr
    raise RuntimeError('operator outside the frozen operator table: '+repr(op))


def main():
    db=sqlite3.connect(':memory:');records=[]
    try:
        db.execute('CREATE TABLE facts(k INTEGER,alt INTEGER NOT NULL)')
        db.executemany('INSERT INTO facts(k,alt) VALUES (?,?)',[(None,9),(1,10),(1,20),(2,30)])
        for name,expr in CASES:
            for op in ('order','group'):
                sql=build_statement(op,expr)
                try:
                    cur=db.execute(sql)
                    records.append({'case':op+'_'+name,'sql':sql,'status':'ok',
                                    'columns':[x[0] for x in cur.description],'rows':[list(x) for x in cur.fetchall()]})
                except sqlite3.Error as error:
                    records.append({'case':op+'_'+name,'sql':sql,'status':'error',
                                    'error_type':type(error).__name__,'message':str(error)})
    finally:db.close()
    if len(records)!=12:raise RuntimeError('incomplete SQLite reference')
    out={'status':'sqlite-reference-complete','sqlite_version':sqlite3.sqlite_version,'records':records,
         'scope':'SQLite synthetic facts; tie order not asserted for ORDER BY constants; no old-engine run'}
    with (HERE/'sqlite-reference.json').open('x',encoding='utf8',newline='\n') as f:
        json.dump(out,f,indent=2);f.write('\n')
    print(json.dumps({'status':out['status'],'cases':12,'sqlite_version':sqlite3.sqlite_version}))


if __name__=='__main__':main()
