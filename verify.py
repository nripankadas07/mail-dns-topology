"""Meaningful source checks plus clean installed CLI behavior outside source."""
import json, os, pathlib, subprocess, sys, tempfile, venv
ROOT=pathlib.Path(__file__).resolve().parent
MODULE='mail_dns_topology'
COMMAND='mail-dns-topology'
subprocess.run([sys.executable,'-m','unittest','discover','-v'],cwd=ROOT,check=True)
subprocess.run([sys.executable,'-m','compileall','-q',MODULE+'.py'],cwd=ROOT,check=True)
subprocess.run([sys.executable,'demo.py'],cwd=ROOT,check=True)
with tempfile.TemporaryDirectory() as d:
    env=pathlib.Path(d)/'env';venv.EnvBuilder(with_pip=True).create(env)
    py=env/('Scripts/python.exe' if sys.platform=='win32' else 'bin/python')
    subprocess.run([str(py),'-m','pip','install','--disable-pip-version-check',str(ROOT)],check=True)
    command=env/('Scripts/'+COMMAND+'.exe' if sys.platform=='win32' else 'bin/'+COMMAND)
    for case in json.loads((ROOT/'smoke.json').read_text()):
        args=[str(ROOT/x) if (ROOT/x).is_file() else x for x in case['args']]
        environ=os.environ.copy()
        if COMMAND=='webhook-window-guard':environ['WEBHOOK_WINDOW_SECRET']='MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY='
        r=subprocess.run([str(command),*args],cwd=d,env=environ,capture_output=True,text=True)
        if r.returncode!=case['exit']:raise RuntimeError('installed CLI contract failed: '+r.stdout+r.stderr)
        data=json.loads(r.stdout)
        if case['exit']==2 and 'error' not in data:raise RuntimeError('invalid input needs structured error')
    print('PASS: fresh package installation and installed CLI good/findings/invalid cases outside source')
