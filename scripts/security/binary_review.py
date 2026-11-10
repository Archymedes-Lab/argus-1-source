"""Bounded static ELF hardening and entry-point disassembly; never executes input."""
import argparse
import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path

MAX_BYTES = 512 * 1024 * 1024
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552


class InvalidBinary(ValueError):
    pass


def elf(data):
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise InvalidBinary('only ELF64 little-endian is supported')
    _, kind, machine, version, entry, phoff, _, _, ehsize, phsize, phnum, _, _, _ = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    if version != 1 or ehsize != 64 or phsize != 56 or phnum > 4096 or phoff + phsize * phnum > len(data):
        raise InvalidBinary('invalid program headers')
    segments = []
    for index in range(phnum):
        row = struct.unpack_from('<IIQQQQQQ', data, phoff + index * phsize)
        segment, flags, offset, address, _, filesz, memsz, _ = row
        if offset + filesz > len(data) or filesz > memsz:
            raise InvalidBinary('invalid segment bounds')
        segments.append((segment, flags, offset, address, filesz, memsz))
    dynamic = {}
    for segment, _, offset, _, filesz, _ in segments:
        if segment != PT_DYNAMIC:
            continue
        if filesz > 1024 * 1024 or filesz % 16:
            raise InvalidBinary('dynamic table bound')
        for pos in range(offset, offset + filesz, 16):
            tag, value = struct.unpack_from('<QQ', data, pos)
            if tag == 0:
                break
            dynamic.setdefault(tag, []).append(value)
    bind_now = (24 in dynamic or any(value & 8 for value in dynamic.get(30, []))
                or any(value & 1 for value in dynamic.get(0x6FFFFFFB, [])))
    paths = []
    if 15 in dynamic or 29 in dynamic:
        tables = dynamic.get(5, [])
        if len(tables) != 1:
            raise InvalidBinary('missing string table')
        base = next((offset + tables[0] - address for segment, _, offset, address, filesz, _ in segments
                     if segment == PT_LOAD and address <= tables[0] < address + filesz), None)
        if base is None:
            raise InvalidBinary('invalid string table address')
        for tag in (15, 29):
            for value in dynamic.get(tag, []):
                start = base + value
                end = data.find(b'\0', start, min(len(data), start + 65536))
                if end < 0:
                    raise InvalidBinary('unterminated search path')
                paths.extend(data[start:end].decode('utf-8', 'strict').split(':'))
    checks = {
        'position_independent_executable': kind == 3 and entry > 0 and any(s[0] == PT_INTERP for s in segments),
        'non_executable_stack': any(s[0] == PT_GNU_STACK and not s[1] & 1 for s in segments),
        'no_writable_executable_load': not any(s[0] == PT_LOAD and s[1] & 3 == 3 for s in segments),
        'full_relro': any(s[0] == PT_GNU_RELRO for s in segments) and bind_now,
        'relative_library_search_only': all(path == '$ORIGIN' or path.startswith('$ORIGIN/') for path in paths),
        'entry_in_executable_load': any(s[0] == PT_LOAD and s[1] & 1 and s[3] <= entry < s[3] + s[4] for s in segments),
    }
    return {'format': 'ELF64-LE', 'machine': machine, 'entry': entry, 'checks': checks,
            'segments': len(segments), 'library_search_entries': len(paths)}


def review(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
            raise InvalidBinary('artifact must be a bounded regular file')
        data = file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise InvalidBinary('artifact grew past bound')
    report = elf(data)
    report.update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                  human_review_required=True, provenance='caller-selected artifact; no signing claim')
    tool = shutil.which('objdump')
    if not tool:
        report['disassembly'] = 'unavailable'
        return report, 2
    # /proc/self/fd cannot identify the closed descriptor: disassemble an immutable
    # private copy, so a caller cannot substitute an artifact after hashing it.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='argus-binary-') as scratch:
        copy = Path(scratch) / 'artifact'
        copy.write_bytes(data)
        root = Path(__file__).resolve().parents[2]
        sys.path.insert(0, str(root))
        from scripts.security.campaign import Step, execute
        output = bytearray()
        result = execute(Step('entry-disassembly', 'binary', (tool, '-d',
                         '--start-address=' + str(report['entry']),
                         '--stop-address=' + str(report['entry'] + 4096), str(copy))),
                         Path(scratch) / 'home', timeout=20, output_consumer=output.extend)
        if result['status'] != 'passed':
            report['disassembly'] = 'incomplete'
            return report, 2
        import re
        instructions = sum(bool(re.match(rb'^\s*[0-9a-f]+:\s+[0-9a-f]{2}', line))
                           for line in output.splitlines())
    report['disassembly'] = {'instructions': instructions, 'sha256': result['output_sha256']}
    if not instructions:
        return report, 2
    return report, 0 if all(report['checks'].values()) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path)
    args = parser.parse_args()
    try:
        report, code = review(args.artifact)
    except (OSError, ValueError, struct.error, subprocess.SubprocessError):
        report, code = {'status': 'incomplete', 'reason': 'artifact rejected or analyzer unavailable'}, 2
    print(json.dumps(report))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
