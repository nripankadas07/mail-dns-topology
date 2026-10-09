import json
from pathlib import Path
import mail_dns_topology as m
good=m.audit(json.loads(Path('snapshot.json').read_text()));bad=m.audit(json.loads(Path('bad-snapshot.json').read_text()))
assert not good['findings'] and bad['findings']
print(json.dumps({'good':good,'violation':bad},indent=2))
