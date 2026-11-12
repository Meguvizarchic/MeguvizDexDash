#!/usr/bin/env python3
"""Record SQLite integer-ordinal boundaries without touching existing records."""
import json
from pathlib import Path
import sqlite3

HERE=Path(__file__).resolve().parent
LITERALS=('2147483647','2147483648','-2147483647','-2147483648','+2147483648','1.0')
OPERATORS=('ORDER BY','GROUP BY')


def build_statement(operator, expression):
    """Compose a statement from this file's frozen literal tables only.

    Both arguments must be members of the module constants above, so no value
    outside this script can reach the statement text.
    """
    if expression not in LITERALS:
        raise RuntimeError('expression outside the frozen literal table: '+repr(expression))
    if operator not in OPERATORS:
        raise RuntimeError('operator outside the frozen operator table: '+repr(operator))
    return 'SELECT v FROM t '+operator+' '+expression


def main():
    db=sqlite3.connect(':memory:'); records=[]
    try:
        db.execute('CREATE TABLE t(v INTEGER)');db.executemany('INSERT INTO t VALUES (?)',[(1,),(2,)])
        for expression in LITERALS:
            for op in OPERATORS:
                sql=build_statement(op,expression)
                try:
                    cursor=db.execute(sql)
                    records.append({'expression':expression,'operator':op,'sql':sql,'status':'ok',
                                    'rows':[list(row) for row in cursor.fetchall()]})
                except sqlite3.Error as error:
                    records.append({'expression':expression,'operator':op,'sql':sql,'status':'error',
                                    'error_type':type(error).__name__,'message':str(error)})
    finally:db.close()
    if len(records)!=12:raise RuntimeError('incomplete integer-boundary reference')
    output={'status':'sqlite-reference-complete','sqlite_version':sqlite3.sqlite_version,'records':records,
            'scope':'SQLite-only synthetic integer boundaries; A0/A1 not started'}
    with (HERE/'sqlite-integer-boundaries.json').open('x',encoding='utf8',newline='\n') as f:
        json.dump(output,f,indent=2);f.write('\n')
    print(json.dumps({'status':output['status'],'cases':len(records),'sqlite_version':sqlite3.sqlite_version}))


if __name__=='__main__':main()
