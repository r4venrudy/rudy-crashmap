"""Independent struct-generated captures, byte-level oracles, and command contracts."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import random
import re
import struct
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
parser.add_argument('root', type=Path)
parser.add_argument('--dotnet', default='dotnet')
args = parser.parse_args()
binary, root = args.binary.resolve(), args.root.resolve()
command = [args.dotnet, str(binary)] if binary.suffix == '.dll' else [str(binary)]
checks = 0
def check(condition, message):
    global checks
    checks += 1
    assert condition, message
def run(*arguments, code=0):
    result = subprocess.run([*command, *map(str, arguments)], capture_output=True, text=True, encoding='utf-8', timeout=20)
    check(result.returncode == code, str(arguments) + '\n' + result.stdout + result.stderr)
    return result
def report(*arguments, code=0):
    return json.loads(run(*arguments, '--format', 'json', code=code).stdout)
spec = importlib.util.spec_from_file_location('synthetic', root / 'examples/make_capture.py')
synthetic = importlib.util.module_from_spec(spec);spec.loader.exec_module(synthetic)
def directory(raw):
    count, offset = struct.unpack_from('<II', raw, 8)
    return [struct.unpack_from('<III', raw, offset + i*12) for i in range(count)]

with tempfile.TemporaryDirectory(prefix='crashmap-contract-') as temp_name:
    temp = Path(temp_name)
    capture = temp / 'captur\u00e9 \u0130';expected = synthetic.create(capture)
    before, after = capture/'before.dmp', capture/'after.dmp'
    original = before.read_bytes(); initial = hashlib.sha256(original).hexdigest()
    j = report('inspect', before)
    check(j['input']['sha256'] == expected['sha256']['before.dmp'], 'Input SHA-256 independently matches')
    check(j['summary']['modules'] == 2 and j['summary']['threads'] == 1 and j['summary']['captureDescriptors'] == 5, 'Native counts match independent fixture')
    check(j['summary']['distinctCapturedBytes'] == 160 and j['summary']['privateExecutableRegions'] == 1 and j['summary']['writableExecutableRegions'] == 1, 'Union avoids duplicate-stack double counting')
    check(j['exception']['threadPresent'] and j['exception']['captured'] and j['exception']['modules'][0]['offset'] == '0x0000000000001010', 'Exception mapped to captured module offset')
    check(j['validation']['skippedStreamTypes'] == [0x47670001] and j['validation']['headerChecksum'] == 'not-verified', 'Unknown coverage and checksum boundaries are explicit')
    check(j['input']['system']['architectureName'] == 'amd64', 'System architecture parsed')
    check(j['modules'][0]['module']['pdbIdentity'] == '123456789abcdef0123456789abcdef0-1', 'RSDS GUID and age parsed in little-endian GUID layout')
    limited = report('inspect', before, '--rows', 1)
    check(limited['summary'] == j['summary'] and limited['omitted']['modules'] == 1 and limited['omitted']['memory'] == 4, 'Display limit preserves full summary')
    report('inspect', before, '--fail-on', 'private-executable', code=1)
    loc = report('locate', before, '--address', '0x20002f')
    check(loc['summary']['captureDescriptors'] == 1, 'Memory64 last-byte location')
    raw_rva = next(e for e in directory(original) if e[0] == 9)[2]
    payload = struct.unpack_from('<Q', original, raw_rva+8)[0]
    check(loc['captures'][0]['matchingFileOffset'] == payload+47, 'Memory64 file-offset oracle')
    check(report('locate', before, '--address', '200030')['summary']['captureDescriptors'] == 0, 'End-exclusive address boundary')
    check(report('locate', before, '--address', '700000')['summary']['captureDescriptors'] == 2, 'Overlapping capture sources remain visible')
    check(report('locate', before, '--address', 'ffffffffffffffff')['summary']['modules'] == 0, 'Unsigned 64-bit address parsing')
    diff = report('diff', before, after, '--fail-on', 'changed', code=1)
    for key, value in expected['difference'].items(): check(diff['summary'][key] == value, 'Module change oracle '+key)
    check(not report('diff', before, before, '--fail-on', 'changed')['summary']['changed'], 'Identical dumps do not reach the gate')
    check(report('diff', before, capture/'ambiguous.dmp')['summary']['ambiguous'] == 1, 'Duplicate basenames cannot be arbitrarily paired')
    relocated = bytearray(original)
    module_rva = next(e for e in directory(original) if e[0] == 4)[2]
    struct.pack_into('<Q', relocated, module_rva+4, 0x150000000)
    relocation = temp/'relocated.dmp';relocation.write_bytes(relocated)
    relocation_report = report('diff', before, relocation, '--fail-on', 'changed')
    check(relocation_report['summary']['relocated'] == 1 and not relocation_report['summary']['changed'], 'ASLR-only relocation does not count as metadata drift')
    html = run('inspect', capture/'hostile-name.dmp', '--format', 'html').stdout
    check('<script>' not in html and '<img src=x' not in html and 'Content-Security-Policy' in html and 'Rudy CrashMap' in html, 'HTML is script-free and encodes hostile names')
    for secret in ['lab-private', 'other-private', 'secret.pdb', 'INVENTED MEMORY CONTENT', str(capture)]:
        check(secret not in html, 'Report omits source paths and raw payloads')
    output = temp/'evidence \u00e9.html'
    run('inspect', before, '--format', 'html', '--output', output)
    check(output.exists(), 'Unicode output created')
    saved = output.read_bytes()
    run('inspect', before, '--output', output, code=2)
    check(output.read_bytes() == saved, 'Existing reports are never replaced')
    if os.name != 'nt':check(output.stat().st_mode & 0o777 == 0o600, 'POSIX evidence output is private')
    alias = temp/'source-alias.dmp';os.link(before, alias)
    run('inspect', before, '--output', alias, code=2)
    check(hashlib.sha256(before.read_bytes()).hexdigest() == initial, 'Source aliases cannot be overwritten')
    if os.name != 'nt':
        symbolic = temp/'source-symlink.dmp';symbolic.symlink_to(before)
        run('inspect', symbolic, code=2)
    run('--help');check(run('--version').stdout.strip() == 'crashmap 0.1.1-preview', 'Version contract')
    for kind in [4,16]:
        raw=bytearray(original);entry=next(i for i,e in enumerate(directory(original)) if e[0]==kind)
        struct.pack_into('<I',raw,32+entry*12,0x60000000+kind)
        partial=temp/('missing-stream-'+str(kind)+'.dmp');partial.write_bytes(raw)
        partial_report=report('inspect',partial)
        check(kind not in partial_report['input']['streamTypes'],'Partial inspection exposes missing stream '+str(kind))
        if kind==4:
            run('diff',before,partial,'--fail-on','changed',code=2)
            run('diff',partial,before,code=2)
        else:run('inspect',partial,'--fail-on','private-executable',code=2)
    for tail in [[], ['--rows','0'], ['--rows','1001'], ['--rows','1','--rows','2'], ['--unknown','yes'], ['--format','yaml'], ['--format'], ['--max-items','0'], ['--max-input-mib','4097'], ['--address','1'], ['--fail-on','changed']]:
        if tail:run('inspect', before, *tail, code=2)
    for command_args in [('diff', before), ('locate',before), ('locate',before,'--address','xyz'), ('locate',before,'--address','-1'), ('locate',before,'--address','1'*17), ('locate',before,'--address','1','--fail-on','changed'), ('diff',before,after,'--fail-on','private-executable')]: run(*command_args,code=2)
    run('inspect', before, '--max-items', 1, code=2)
    many = bytearray(44)
    struct.pack_into('<IIIIIIQ',many,0,0x504d444d,0xa793,1,32,0,0,0)
    module = bytearray(108)
    name_offset = 44 + 4 + 3000*108
    struct.pack_into('<QIIII',module,0,0x1000,0x1000,0,0,name_offset)
    many.extend(struct.pack('<I',3000) + module*3000 + struct.pack('<I',8192) + ('a'*4096).encode('utf-16-le'))
    struct.pack_into('<III',many,32,4,4+3000*108,44)
    string_budget = temp/'string-budget.dmp';string_budget.write_bytes(many)
    check('Aggregate decoded string budget' in run('inspect',string_budget,code=2).stderr,'Repeated RVA strings still consume the aggregate decoding budget')
    oversized = temp/'oversized.dmp';oversized.write_bytes(original + bytes(1024*1024))
    run('inspect',oversized,'--max-input-mib',1,code=2)
    # Every known stream count/size/RVA, and its nested locations, is untrusted.
    variants = []
    def variant(name, offset, fmt, value):
        raw=bytearray(original);struct.pack_into(fmt,raw,offset,value);variants.append((name,bytes(raw)))
    variant('signature',0,'<I',0)
    variant('version',4,'<I',0)
    variant('directory-count',8,'<I',257)
    variant('directory-rva',12,'<I',0xffffffff)
    variant('unsupported-encoding-flags',24,'<Q',0x8000000000000000)
    for i,(kind,size,rva) in enumerate(directory(original)):
        variant('stream-rva-'+str(kind),32+i*12+8,'<I',0xffffffff)
        variant('stream-extent-'+str(kind),32+i*12+4,'<I',0xffffffff)
        if kind in (3,4,5):variant('count-'+str(kind),rva,'<I',0xffffffff)
        if kind in (9,16):variant('wide-count-'+str(kind),rva+(8 if kind==16 else 0),'<Q',0xffffffffffffffff)
    name_rva=struct.unpack_from('<I',original,module_rva+4+20)[0]
    variant('odd-utf16',name_rva,'<I',3)
    variant('oversized-string',name_rva,'<I',9000)
    variant('invalid-surrogate',name_rva+4,'<H',0xd800)
    variant('virtual-overflow',module_rva+4,'<Q',0xffffffffffffffff)
    memory64 = next(e[2] for e in directory(original) if e[0]==9)
    variant('memory64-payload',memory64+8,'<Q',0xffffffffffffffff)
    meminfo = next(e[2] for e in directory(original) if e[0]==16)
    variant('short-region-stride',meminfo+4,'<I',4)
    variant('region-header-extent',meminfo,'<I',0xffffffff)
    exception = next(e[2] for e in directory(original) if e[0]==6)
    variant('exception-parameters',exception+32,'<I',16)
    variant('exception-context',exception+164,'<I',0xffffffff)
    variant('duplicate-stream',32+7*12,'<I',7)
    for size in [0,1,7,16,31,32,127,len(original)-1]:variants.append(('truncated-'+str(size),original[:size]))
    for name,raw in variants:
        path=temp/(name+'.dmp');path.write_bytes(raw)
        failed=run('inspect',path,code=2)
        check(failed.stdout == '' and 'Unhandled exception' not in failed.stderr, 'Invalid metadata emits only a controlled error: '+name)
    # A mutation need not be invalid, but it must never escape through an unhandled parser failure.
    rng=random.Random(7741)
    for i in range(80):
        raw=bytearray(original);pos=rng.randrange(len(raw));raw[pos]^=rng.randrange(1,256)
        path=temp/'mutation.dmp';path.write_bytes(raw)
        result=subprocess.run([*command,'inspect',str(path),'--format','json'],capture_output=True,text=True,encoding='utf-8',timeout=20)
        check(result.returncode in (0,2) and 'Unhandled exception' not in result.stderr,'Bounded mutation '+str(i))
        if result.returncode==0:json.loads(result.stdout)
    check(before.read_bytes() == original, 'Original evidence unchanged after complete suite')
    # Keep installed instructions honest: all local Markdown targets must exist.
    for path in [root/'README.md',*sorted((root/'docs').glob('*.md'))]:
        if not path.exists():continue
        for target in re.findall(r'\]\(([^)#]+)(?:#[^)]*)?\)',path.read_text(encoding='utf-8')):
            if '://' not in target:check((path.parent/target).exists(),'Documentation target '+target)
print(f'CrashMap independent CLI assertions passed: {checks}; synthetic binary oracle, strict bounds, coverage, comparison, privacy, mutation and output contracts.')
