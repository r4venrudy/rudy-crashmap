"""Generate invented minidumps from documented layouts, never from a real process."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import uuid

def build(after=False, duplicate=False, hostile=False):
    count = 8
    data = bytearray(32 + count * 12)
    streams = []
    def append(payload):
        position = len(data); data.extend(payload); return position
    def string(text):
        encoded = text.encode('utf-16-le'); return append(struct.pack('<I', len(encoded)) + encoded)
    def stream(kind, body):
        streams.append((kind, len(body), append(body)))
    csd = string('invented lab')
    system = bytearray(56)
    struct.pack_into('<HHHBBIIIII', system, 0, 9, 0, 0, 4, 1, 10, 0, 26000, 2, csd)
    stream(7, system)
    name = '<img src=x onerror=alert(1)>.dll' if hostile else 'sample.dll'
    names = [f'C:\\synthetic\\lab-private\\{name}', 'C:\\synthetic\\core.dll']
    if after: names.append('C:\\synthetic\\agent.dll')
    if duplicate: names.append('D:\\other-private\\sample.dll')
    modules = bytearray(struct.pack('<I', len(names)))
    for i, full in enumerate(names):
        name_rva = string(full)
        identifier = uuid.UUID('12345678-9abc-def0-1234-56789abcdef0')
        if after and i == 0: identifier = uuid.UUID('87654321-cba9-0fed-4321-0fedcba98765')
        cv = b'RSDS' + identifier.bytes_le + struct.pack('<I', 1) + b'C:\\private\\symbols\\secret.pdb\0'
        cv_rva = append(cv)
        module = bytearray(108)
        base = [0x140000000, 0x190000000 if after else 0x180000000, 0x1a0000000][i]
        struct.pack_into('<QIIII', module, 0, base, 0x4000 if after and i == 0 else 0x3000, 123, 1710000001 if after and i == 0 else 1710000000, name_rva)
        struct.pack_into('<II', module, 76, len(cv), cv_rva)
        modules.extend(module)
    stream(4, modules)
    stack_rva = append(bytes(range(32)))
    context_rva = append(bytes(64))
    thread = bytearray(48)
    struct.pack_into('<I', thread, 0, 101)
    struct.pack_into('<QIIII', thread, 24, 0x700000, 32, stack_rva, 64, context_rva)
    stream(3, struct.pack('<I', 1) + thread)
    code_rva = append(b'INVENTED MEMORY CONTENT NOT FOR REPORTS'.ljust(64, b'.'))
    stream(5, struct.pack('<I', 2) + struct.pack('<QII', 0x140001000, 64, code_rva) + struct.pack('<QII', 0x700000, 32, stack_rva))
    raw_rva = append(b'A' * 48 + b'B' * 16)
    stream(9, struct.pack('<QQ', 2, raw_rva) + struct.pack('<QQQQ', 0x200000, 48, 0x200100, 16))
    regions = bytearray(struct.pack('<IIQ', 16, 48, 3))
    for base, size, protect, kind in [(0x200000, 0x2000, 0x40, 0x20000), (0x140000000, 0x3000, 0x20, 0x1000000), (0x700000, 0x1000, 4, 0x20000)]:
        regions.extend(struct.pack('<QQIIQIIII', base, base, protect, 0, size, 0x1000, protect, kind, 0))
    stream(16, regions)
    exception = bytearray(168)
    struct.pack_into('<I', exception, 0, 101)
    struct.pack_into('<IIQQII', exception, 8, 0xc0000005, 0, 0, 0x140001010, 2, 0)
    struct.pack_into('<II', exception, 160, 64, context_rva)
    stream(6, exception)
    stream(0x47670001, b'unknown synthetic extension')
    struct.pack_into('<IIIIIIQ', data, 0, 0x504d444d, 0xa793, count, 32, 0, 1710000000, 0x800)
    for i, entry in enumerate(streams): struct.pack_into('<III', data, 32 + i * 12, *entry)
    return bytes(data)

def create(destination):
    destination = Path(destination); destination.mkdir(parents=True, exist_ok=False)
    files = {'before.dmp': build(), 'after.dmp': build(after=True), 'ambiguous.dmp': build(duplicate=True), 'hostile-name.dmp': build(hostile=True)}
    for name, raw in files.items(): (destination / name).write_bytes(raw)
    expected = {'schema': 'rudy-crashmap/synthetic-v1', 'sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}, 'distinctCapturedBytes': 160, 'beforeModules': 2, 'threads': 1, 'captureDescriptors': 5, 'privateExecutableRegions': 1, 'difference': {'added': 1, 'removed': 0, 'metadataChanged': 1, 'relocated': 1, 'ambiguous': 0}}
    (destination / 'expected.json').write_text(json.dumps(expected, indent=2) + '\n', encoding='utf-8')
    return expected

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('new_directory',type=Path)
    args=parser.parse_args();create(args.new_directory)
    print('Created four invented minidumps and independent expected metadata.')
