"""Audit a captured mail-DNS dependency graph; never query live DNS."""
import argparse
import ipaddress
import json
import re
from pathlib import Path


def domain(value):
    if not isinstance(value, str) or len(value) > 254:
        raise ValueError('invalid ASCII DNS name')
    value = value.rstrip('.').lower()
    if not value or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', x) for x in value.split('.')):
        raise ValueError('invalid ASCII DNS name')
    return value


def tags(text):
    result = {}
    for part in text.split(';'):
        if not part.strip():
            continue
        if '=' not in part:
            raise ValueError('TXT tag requires equals sign')
        key, value = [v.strip() for v in part.split('=', 1)]
        key = key.lower()
        if key in result:
            raise ValueError('duplicate TXT tag')
        result[key] = value
    return result


def audit(snapshot):
    if not isinstance(snapshot, dict) or set(snapshot) != {'domain','selectors','records'}:
        raise ValueError('snapshot requires domain, selectors and records only')
    root = domain(snapshot['domain'])
    if not isinstance(snapshot['selectors'], list) or len(snapshot['selectors']) > 100:
        raise ValueError('selectors must be a list of at most 100 labels')
    selectors = snapshot['selectors']
    if any(not isinstance(s,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,63}',s) for s in selectors) or len(set(s.lower() for s in selectors)) != len(selectors):
        raise ValueError('invalid or duplicate selector')
    records = snapshot['records']
    if not isinstance(records,list) or len(records) > 10000:
        raise ValueError('records must be a list of at most 10000 records')
    table = {}
    for r in records:
        if not isinstance(r,dict) or not {'name','type'} <= set(r):
            raise ValueError('invalid DNS record')
        owner, kind = domain(r['name']), r['type']
        fields = {'TXT': {'name','type','chunks'}, 'MX': {'name','type','target','priority'}, 'A': {'name','type','address'}, 'AAAA': {'name','type','address'}}
        if kind not in fields or set(r) != fields[kind]:
            raise ValueError('only declared TXT, MX, A, AAAA fields supported')
        if kind == 'TXT':
            if not isinstance(r['chunks'],list) or not r['chunks'] or any(not isinstance(x,str) or len(x.encode('utf-8')) > 255 for x in r['chunks']):
                raise ValueError('TXT chunks must be strings up to 255 UTF-8 bytes each')
            value = ''.join(r['chunks'])
        elif kind == 'MX':
            if type(r['priority']) is not int or not 0 <= r['priority'] <= 65535:
                raise ValueError('invalid MX priority')
            value = domain(r['target'])
        else:
            address = ipaddress.ip_address(r['address'])
            if address.version != (4 if kind == 'A' else 6):
                raise ValueError('address family does not match record type')
            value = str(address)
        table.setdefault((owner,kind),[]).append(value)
    findings, edges = [], []
    def add(code, owner, **details):
        findings.append(dict(code=code, owner=owner, **details))
    def selected(owner, version):
        texts = [v for v in table.get((owner,'TXT'),[]) if v.split(None,1) and v.split(None,1)[0].lower() == version.lower()]
        return texts
    graph = {}
    pending, visited = [root], set()
    while pending:
        owner = pending.pop()
        if owner in visited:
            continue
        visited.add(owner)
        spfs = selected(owner,'v=spf1')
        if len(spfs) != 1:
            add('spf_record_count',owner,actual=len(spfs))
            graph[owner] = []
            continue
        graph[owner] = []
        redirects = 0
        for token in spfs[0].split()[1:]:
            mechanism = token.lstrip('+~-?')
            if mechanism.startswith('include:') or token.startswith('redirect='):
                kind = 'redirect' if token.startswith('redirect=') else 'include'
                target = token.split('=',1)[1] if kind == 'redirect' else mechanism.split(':',1)[1]
                if '%' in target:
                    add('unsupported_macro',owner)
                    continue
                target = domain(target)
                redirects += kind == 'redirect'
                graph[owner].append(target)
                edges.append(dict(source=owner,target=target,kind=kind))
                pending.append(target)
            elif mechanism in ('all',):
                pass
            elif mechanism.startswith(('ip4:','ip6:')):
                network = ipaddress.ip_network(mechanism.split(':',1)[1], strict=False)
                if network.version != (4 if mechanism.startswith('ip4:') else 6):
                    raise ValueError('SPF network family mismatch')
            else:
                add('unsupported_spf_term',owner,term=token)
        if redirects > 1:
            add('multiple_redirects',owner)
    # Iterative three-colour traversal avoids recursive-stack failures.
    colour = {}
    for origin in graph:
        if colour.get(origin):
            continue
        stack = [(origin, iter(graph[origin]))]
        colour[origin] = 1
        while stack:
            owner, children = stack[-1]
            child = next(children, None)
            if child is None:
                colour[owner] = 2
                stack.pop()
            elif colour.get(child) == 1:
                add('spf_cycle',owner,target=child)
            elif not colour.get(child):
                colour[child] = 1
                stack.append((child, iter(graph.get(child,[]))))
    dmarc_owner = '_dmarc.'+root
    dm = [v for v in table.get((dmarc_owner,'TXT'),[]) if re.match(r'^v=DMARC1\s*(?:;|$)',v,re.I)]
    if len(dm) != 1:
        add('dmarc_record_count',dmarc_owner,actual=len(dm))
    else:
        t = tags(dm[0])
        if t.get('p') not in ('none','quarantine','reject'):
            add('dmarc_policy',dmarc_owner)
    for selector in selectors:
        owner = selector.lower()+'._domainkey.'+root
        values = table.get((owner,'TXT'),[])
        if len(values) != 1:
            add('dkim_record_count',owner,actual=len(values))
        else:
            t = tags(values[0])
            if t.get('v','DKIM1') != 'DKIM1' or not t.get('p'):
                add('dkim_key_missing_or_revoked',owner)
    mx = table.get((root,'MX'),[])
    if not mx:
        add('mx_missing',root)
    for target in mx:
        if not table.get((target,'A')) and not table.get((target,'AAAA')):
            add('mx_address_missing',root,target=target)
    return dict(domain=root, spf_nodes=len(visited), edges=edges, findings=findings)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('snapshot')
    args = ap.parse_args()
    try:
        data = Path(args.snapshot).read_bytes()
        if len(data) > 2*1024*1024:
            raise ValueError('snapshot exceeds 2 MiB')
        result = audit(json.loads(data))
        print(json.dumps(result,sort_keys=True))
        return int(bool(result['findings']))
    except (ValueError, OSError, UnicodeError, TypeError) as e:
        print(json.dumps({'error': str(e)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
