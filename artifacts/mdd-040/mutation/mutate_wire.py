"""Mutation checks for mdd-wire/1 and the worker protocol.

Each mutation edits one source line, runs the named test command and must make it
fail; the file is restored afterwards and a clean run confirms the tree.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path('.')
FRAME = ROOT / 'crates/mdd-wire/src/frame.rs'
STREAM = ROOT / 'crates/mdd-wire/src/stream.rs'
CELL = ROOT / 'crates/mdd-wire/src/cell.rs'
CREDIT = ROOT / 'crates/mdd-wire/src/credit.rs'
CHANNEL = ROOT / 'crates/mdd-wire/src/channel.rs'
ERROR = ROOT / 'crates/mdd-wire/src/error.rs'
PROTOCOL = ROOT / 'crates/mdd-worker/src/protocol/mod.rs'

WIRE = ['cargo', 'test', '--offline', '--locked', '-p', 'mdd-wire']
CHILD = ['cargo', 'test', '--offline', '--locked', '-p', 'mdd-worker', '--test', 'wire_child']

MUTATIONS = [
    ('body length is not checked against the limit', FRAME, 'if body_bytes > max_body_bytes {', 'if false {', WIRE),
    ('unknown required flags are accepted', FRAME, 'if flags & REQUIRED_FLAGS_MASK != 0 {', 'if false {', WIRE),
    ('header length is not checked', FRAME, 'if header_bytes as usize != HEADER_BYTES {', 'if false {', WIRE),
    ('a short body is returned as a frame', FRAME, 'if got as u64 != wanted {', 'if false {', WIRE),
    ('frames are written to any channel', FRAME, 'if channel != ChannelKind::Dedicated {', 'if false {', WIRE),
    ('batch sequence is not checked', STREAM, 'if sequence != self.next_sequence {', 'if false {', WIRE),
    ('End digest is not compared', STREAM, 'if summary.digest != digest.finish() {', 'if false {', WIRE),
    ('End counts are not compared', STREAM,
     'if summary.rows != self.rows.len() as u64 || summary.batches != self.next_sequence {', 'if false {', WIRE),
    ('frames after a terminal are accepted', STREAM, 'if self.terminal.is_some() {', 'if false {', WIRE),
    ('NULL is absent from the digest', CELL, 'Self::Null => out.push(0),', 'Self::Null => {}', WIRE),
    ('non-canonical decimals are accepted', CELL, 'if value.to_string() != text {', 'if false {', WIRE),
    ('unknown cell fields are accepted', CELL,
     'match object.keys().find(|key| !allowed.contains(&key.as_str())) {',
     'match object.keys().find(|key| !allowed.contains(&key.as_str()) && false) {', WIRE),
    ('the per-cell hard limit is ignored', STREAM, 'if cell.payload_bytes() > limits.max_cell_bytes {', 'if false {', WIRE),
    ('NULL is accepted in a non-nullable column', STREAM, 'None if !column.nullable => {', 'None if false => {', WIRE),
    ('credit is not enforced by the consumer', STREAM, 'if self.limits.enforce_credit {', 'if false {', WIRE),
    ('batch credit is not counted', CREDIT, 'if self.remaining.batches == 0 || self.remaining.bytes < bytes {',
     'if self.remaining.bytes < bytes {', WIRE),
    ('a waiting producer ignores cancel', CREDIT, 'if cancel.load(Ordering::SeqCst) {', 'if false {', WIRE),
    ('wire frames may be written to MCP stdout', CHANNEL, 'if bytes.starts_with(&MAGIC) {', 'if false {', WIRE),
    ('negotiation fails on a higher common major', FRAME, '.filter(|(major, _)| *major == MAJOR)', '.filter(|(major, _)| *major >= MAJOR)', WIRE),
    ('Hello is accepted on any stream', FRAME, 'if (kind == FrameKind::Hello) != (u64::from_le_bytes(stream) == 0) {', 'if false {', WIRE),
    ('the writer keeps writing after a failure', FRAME, 'if self.failed {', 'if false {', WIRE),
    ('a truncated frame is not a lost worker', ERROR, 'Self::Disconnected | Self::TruncatedHeader | Self::TruncatedBody => {', 'Self::Disconnected => {', WIRE),
    ('UTF-16 unit counts are not checked', STREAM, '&& mutf8_units(bytes) != Some(*utf16_units)', '&& false', WIRE),
    ('credit waits are not capped', CREDIT, 'wait.min(MAX_WAIT)', 'wait', WIRE),
    ('the client never sends Cancel', PROTOCOL, 'if cancelled && let Some(queue) = &out {', 'if false && let Some(queue) = &out {', CHILD),
    ('oversized batches are not split', PROTOCOL, 'Err(error) if error.kind == WireErrorKind::FrameTooLarge && rows.len() > 1 => {', 'Err(error) if false => {', CHILD),
    ('an unencodable row sends no Error terminal', PROTOCOL, '&producer.error(&error.to_mdd())?,', '&[],', CHILD),
    ('a worker that ended with Error is killed at once', PROTOCOL, 'result.is_ok() || cancelled || ended_by_peer_error,', 'result.is_ok() || cancelled,', CHILD),
    ('trailing frames after End are not read', PROTOCOL, 'if stream.finish_ready() {', 'if false {', CHILD),
    ('credit is re-granted after the deadline', PROTOCOL,
     'config.cancel.load(Ordering::SeqCst) || Instant::now() >= deadline;', 'false;', CHILD),
]


def run(command):
    try:
        done = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=900)
    except subprocess.TimeoutExpired:
        # A hang is a failure of the tests, never a pass.
        return 124, 'timeout'
    return done.returncode, done.stdout + done.stderr


def main():
    bad = 0
    for name, path, old, new, command in MUTATIONS:
        original = path.read_text(encoding='utf-8')
        if original.count(old) != 1:
            print(f'SKIPPED (pattern count {original.count(old)}): {name}')
            bad += 1
            continue
        path.write_text(original.replace(old, new, 1), encoding='utf-8', newline='')
        try:
            code, output = run(command)
        finally:
            path.write_text(original, encoding='utf-8', newline='')
        compile_error = 'error[' in output or 'could not compile' in output
        killed = code != 0 and not compile_error
        print(('KILLED  ' if killed else ('COMPILE-ERROR' if compile_error else 'SURVIVED')) + f': {name}')
        bad += not killed
    for label, command in (('wire', WIRE), ('child', CHILD)):
        code, _ = run(command)
        print(f'restored tree passes ({label}):', code == 0)
        bad += code != 0
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
