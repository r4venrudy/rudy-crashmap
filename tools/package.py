"""Exercise the installed self-contained command and bundle invented examples only."""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
sys.dont_write_bytecode=True
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('stage',type=Path)
parser.add_argument('target',choices=['linux-x64','windows-x64','macos-arm64'])
parser.add_argument('--version',required=True)
parser.add_argument('--dotnet-root',type=Path,default=Path(os.environ.get('DOTNET_ROOT','not-configured')))
args=parser.parse_args()
source=Path(__file__).resolve().parents[1];stage=args.stage.resolve()
binary=stage/'bin'/('crashmap.exe' if os.name=='nt' else 'crashmap')
def run(*arguments,code=0):
    result=subprocess.run([binary,*map(str,arguments)],capture_output=True,text=True,encoding='utf-8',timeout=30)
    assert result.returncode==code,result.stdout+result.stderr
    return result.stdout
assert run('--version').strip()=='crashmap '+args.version
for name in ['README.md','LICENSE','NuGet.Config','SECURITY.md','CONTRIBUTING.md']:shutil.copyfile(source/name,stage/name)
for name in ['docs','assets','examples']:shutil.copytree(source/name,stage/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
licenses=stage/'licenses';licenses.mkdir()
for name in ['LICENSE.txt','ThirdPartyNotices.txt']:
    location=args.dotnet_root/name
    assert location.is_file(),'SDK runtime license/notice file unavailable: '+name
    shutil.copyfile(location,licenses/('DOTNET-'+name))
runtime=json.loads((stage/'bin/crashmap.runtimeconfig.json').read_text())
assert 'includedFrameworks' in runtime['runtimeOptions'],'A self-contained runtime is required'
(stage/'runtime.json').write_text(json.dumps({'target':args.target,'runtimeOptions':runtime['runtimeOptions']},indent=2)+'\n')
spec=importlib.util.spec_from_file_location('synthetic',source/'examples/make_capture.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
capture=stage/'examples/synthetic';expected=fixture.create(capture)
before,after=capture/'before.dmp',capture/'after.dmp'
inspection=json.loads(run('inspect',before,'--format','json'))
comparison=json.loads(run('diff',before,after,'--format','json','--fail-on','changed',code=1))
assert inspection['summary']['distinctCapturedBytes']==expected['distinctCapturedBytes']
assert inspection['input']['sha256']==expected['sha256']['before.dmp']
assert all(comparison['summary'][key]==value for key,value in expected['difference'].items())
(capture/'inspection.json').write_text(json.dumps(inspection,indent=2)+'\n',encoding='utf-8')
(capture/'comparison.json').write_text(json.dumps(comparison,indent=2)+'\n',encoding='utf-8')
run('inspect',before,'--format','html','--output',capture/'inspection.html')
run('diff',before,after,'--format','html','--output',capture/'comparison.html')
destination=source/'dist';destination.mkdir(exist_ok=True)
name='crashmap-'+args.version+'-'+args.target
output=destination/(name+('.zip' if args.target=='windows-x64' else '.tar.gz'))
assert not output.exists(),'Refusing to replace a package'
files=sorted(p for p in stage.rglob('*') if '__pycache__' not in p.parts and p.suffix!='.pyc')
assert all(not p.is_symlink() for p in files)
if output.suffix=='.zip':
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for file in files:archive.write(file,file.relative_to(stage).as_posix())
else:
    with tarfile.open(output,'x:gz') as archive:
        for file in files:archive.add(file,arcname=file.relative_to(stage).as_posix(),recursive=False)
print('Installed example oracles passed; created',output.name)
