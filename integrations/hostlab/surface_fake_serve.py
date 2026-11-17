#!/usr/bin/env python3
"""A stand-in for `meguvizdexdash serve` that says exactly what a script tells it to, so that the provider's handling of
a stream that is partial, truncated, errored, of another snapshot, mute or broken can be tested. Test support only.

    surface_fake_serve.py SCRIPT.json

SCRIPT: {"opened": <the line to print first, or null for none>,
         "answers": [[line, ...], ...],   # answers[i] is what request i gets; a line is an object, or a string written as it is
         "then": "close" | "exit3" | "hang",
         "deaf_seconds": <sleep this long after the last answer, before reading any further request; 0/absent = none>,
         "log": <a file to which every request is appended as one JSON line, or null>}
In an answer line the string "@id" is replaced by the request's id. When the answers are used up the process does what
"then" says at once ("exit3", "hang"); the default waits for close. "deaf_seconds" makes it stop reading stdin for a
bounded time after the last answer, so that a request write which blocks on a full pipe can be tested.
"""
import json
import sys
import time


def main() -> int:
    script = json.load(open(sys.argv[1], encoding="utf-8"))
    out = sys.stdout
    if script.get("opened") is not None:
        out.write(json.dumps(script["opened"]) + "\n")
        out.flush()
    answers = script.get("answers", [])
    served = 0
    for text in sys.stdin:
        text = text.strip()
        if not text:
            continue
        request = json.loads(text)
        if script.get("log"):
            with open(script["log"], "a", encoding="utf-8") as log:
                log.write(json.dumps(request) + "\n")
        if request.get("op") == "close":
            return 0
        if served >= len(answers):
            break
        for line in answers[served]:
            if isinstance(line, str) and not line.startswith("@"):
                out.write(line + "\n")
                continue
            payload = json.dumps(line).replace('"@id"', json.dumps(request["id"]))
            out.write(payload + "\n")
        out.flush()
        served += 1
        if served >= len(answers):
            if script.get("deaf_seconds"):
                time.sleep(float(script["deaf_seconds"]))
            if script.get("then", "close") != "close":
                break
    then = script.get("then", "close")
    if then == "hang":
        time.sleep(600)
    return 3 if then == "exit3" else 0


if __name__ == "__main__":
    sys.exit(main())
