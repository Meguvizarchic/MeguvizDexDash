"""A stand-in for ``meguvizdexdash serve`` that fails in a chosen way. Used only by test_worker.py.

Usage: python stub_worker.py SCENARIO

It speaks the line protocol (``mdd.cli-stream.v1``) well enough for the SDK's `Worker` and
then does one wrong thing, so each way a worker can go wrong is reached on purpose rather than
by luck: the real binary is used for what it really does (see test_worker.py), this for what
it should not do.
"""
import json
import os
import sys
import time

COMPLETE = {"operation_status": "ok", "execution": {"complete": True},
            "response": {"truncated": False, "more_available": False, "next_cursor": None},
            "coverage": {"input": "complete", "facts": "complete"}}


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def opened():
    emit({"kind": "opened", "protocol": "mdd.cli-stream.v1", "dataset": {"snapshot_id": "stub"}})


def batch(rid, sequence, first_row, values):
    emit({"kind": "batch", "id": rid,
          "batch": {"schema": "mdd.sdk-batch.v1", "sequence": str(sequence), "first_row": str(first_row),
                    "columns": ["n"], "rows": [[{"t": "i64", "v": str(v)}] for v in values]}})


def terminal(rid):
    emit({"kind": "terminal", "id": rid, "terminal": COMPLETE})


def requests():
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        request = json.loads(raw)
        if request.get("op") == "close":
            return
        yield request


def main(scenario):
    if scenario == "crash-before-opened":
        sys.exit(3)
    if scenario == "refuse-before-opened":
        sys.stderr.write(json.dumps({"code": "INVALID_INPUT", "stage": "service", "message": "no such input",
                                     "retryable": False, "details": {}}) + "\n")
        sys.exit(2)
    if scenario == "not-the-protocol":
        emit({"kind": "opened", "protocol": "something-else", "dataset": {}})
        time.sleep(60)
        return
    opened()
    if scenario == "ok":
        for request in requests():
            rid = request["id"]
            batch(rid, 0, 0, [1, 2])
            batch(rid, 1, 2, [3])
            terminal(rid)
        return
    if scenario == "rejected-then-ok":
        for request in requests():
            rid = request["id"]
            if request["sql"] == "bad":
                emit({"kind": "rejected", "id": rid, "error": {"code": "INVALID_ARGUMENT", "stage": "cli.serve",
                                                              "message": "refused", "retryable": False, "details": {}}})
            else:
                batch(rid, 0, 0, [7])
                terminal(rid)
        return
    if scenario == "ignore-close":
        for _ in sys.stdin:
            pass
        time.sleep(600)
        return
    for request in requests():
        rid = request["id"]
        if scenario == "crash-mid-stream":
            batch(rid, 0, 0, [1, 2])
            os._exit(9)
        if scenario == "clean-exit-no-terminal":
            batch(rid, 0, 0, [1])
            sys.exit(0)
        if scenario == "partial-line":
            sys.stdout.write('{"kind":"batch","id":"' + rid + '","batch":{"schema":"mdd.sdk-ba')
            sys.stdout.flush()
            os._exit(0)
        if scenario == "hang":
            time.sleep(600)
        if scenario == "garbage":
            sys.stdout.write("this is not json\n")
            sys.stdout.flush()
            time.sleep(60)
        if scenario == "not-an-object":
            sys.stdout.write("[1,2,3]\n")
            sys.stdout.flush()
            time.sleep(60)
        if scenario == "wrong-id":
            terminal("some-other-request")
            time.sleep(60)
        if scenario == "unknown-kind":
            emit({"kind": "surprise", "id": rid})
            time.sleep(60)
        if scenario == "bad-sequence":
            batch(rid, 1, 0, [1])
            time.sleep(60)
        if scenario == "bad-first-row":
            batch(rid, 0, 0, [1])
            batch(rid, 1, 5, [2])
            time.sleep(60)
        if scenario == "undecodable-batch":
            emit({"kind": "batch", "id": rid, "batch": {"sequence": "0"}})
            time.sleep(60)
        if scenario == "oversize":
            sys.stdout.write("x" * (1 << 20) + "\n")
            sys.stdout.flush()
            time.sleep(60)
        if scenario == "terminal-not-an-object":
            emit({"kind": "terminal", "id": rid, "terminal": "done"})
            time.sleep(60)
        if scenario == "failure-terminal":
            batch(rid, 0, 0, [1])
            emit({"kind": "terminal", "id": rid, "terminal": {
                "operation_status": "error", "error": {"code": "QUOTA_EXCEEDED", "stage": "sql", "message": "too big",
                                                       "retryable": False, "details": {}}}})
        if scenario == "incomplete-terminal":
            batch(rid, 0, 0, [1])
            emit({"kind": "terminal", "id": rid, "terminal": {
                **COMPLETE, "response": {"truncated": True, "more_available": True, "next_cursor": "x"}}})


if __name__ == "__main__":
    main(sys.argv[1])
