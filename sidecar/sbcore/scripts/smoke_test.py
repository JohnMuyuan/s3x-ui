#!/usr/bin/env python3
# Needs: BASE/bin/sbcore-linux-amd64, BASE/sbclient/sing-box (official), BASE/cert/c.{crt,key}.
# Smoke test for sbcore: real client traffic, stats, sessions, hot user swap, kick.
import json, os, subprocess, sys, time, urllib.request

BASE = os.environ.get('SBCORE_SMOKE_BASE', '/root/s3x-test')
TOKEN = 'smoke-token-123'
API = 'http://127.0.0.1:62790'
CERT = {'enabled': True, 'certificate_path': f'{BASE}/cert/c.crt', 'key_path': f'{BASE}/cert/c.key'}
UUID = '7d5a0f3e-1c2b-4e8f-9a6d-3b2c1d0e9f8a'


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(API + path, data=data, method=method, headers={'Authorization': 'Bearer ' + TOKEN})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def inbound(kind, tag, port, users, **extra):
    tls = dict(CERT, alpn=['h3']) if kind in ('hysteria2', 'tuic', 'hysteria') else CERT
    d = {'type': kind, 'tag': tag, 'listen': '127.0.0.1', 'listen_port': port, 'users': users, 'tls': tls}
    d.update(extra)
    return d


ANYTLS = inbound('anytls', 'in-anytls', 41001, [{'name': 'alice', 'password': 'pw-alice'}])
HY2 = inbound('hysteria2', 'in-hy2', 41002, [{'name': 'bob', 'password': 'pw-bob'}])
TUIC = inbound('tuic', 'in-tuic', 41003, [{'name': 'carol', 'uuid': UUID, 'password': 'pw-carol'}], congestion_control='bbr')
HY1 = inbound('hysteria', 'in-hy1', 41005, [{'name': 'erin', 'auth_str': 'pw-erin'}], up_mbps=100, down_mbps=100)
SERVER = {'log': {'level': 'warn'}, 'inbounds': [ANYTLS, HY2, TUIC, HY1],
          'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}

ctls = {'enabled': True, 'insecure': True, 'server_name': 'test.example.com'}
CLIENT = {
    'log': {'level': 'error'},
    'inbounds': [{'type': 'mixed', 'tag': f'm{i}', 'listen': '127.0.0.1', 'listen_port': 42000 + i} for i in (1, 2, 3, 4, 5)],
    'outbounds': [
        {'type': 'hysteria', 'tag': 'o5', 'server': '127.0.0.1', 'server_port': 41005, 'auth_str': 'pw-erin', 'up_mbps': 50, 'down_mbps': 50, 'tls': dict(ctls, alpn=['h3'])},
        {'type': 'anytls', 'tag': 'o1', 'server': '127.0.0.1', 'server_port': 41001, 'password': 'pw-alice', 'tls': ctls},
        {'type': 'hysteria2', 'tag': 'o2', 'server': '127.0.0.1', 'server_port': 41002, 'password': 'pw-bob', 'tls': dict(ctls, alpn=['h3'])},
        {'type': 'tuic', 'tag': 'o3', 'server': '127.0.0.1', 'server_port': 41003, 'uuid': UUID, 'password': 'pw-carol', 'congestion_control': 'bbr', 'tls': dict(ctls, alpn=['h3'])},
        {'type': 'anytls', 'tag': 'o4', 'server': '127.0.0.1', 'server_port': 41001, 'password': 'pw-dave', 'tls': ctls},
    ],
    'route': {'rules': [{'inbound': [f'm{i}'], 'outbound': f'o{i}'} for i in (1, 2, 3, 4, 5)]},
}


def curl(port):
    r = subprocess.run(['curl', '-s', '-m', '12', '-x', f'socks5h://127.0.0.1:{port}', 'https://www.cloudflare.com/cdn-cgi/trace'],
                       capture_output=True, text=True)
    return next((l for l in r.stdout.splitlines() if l.startswith('ip=')), 'FAILED')


def check(label, cond, detail=''):
    print(f"{'PASS' if cond else 'FAIL'}  {label}  {detail}")


env = dict(os.environ, SBCORE_TOKEN=TOKEN)
srv = subprocess.Popen([f'{BASE}/bin/sbcore-linux-amd64'], env=env, stderr=open('/tmp/sbcore.log', 'w'))
json.dump(CLIENT, open('/tmp/sbclient.json', 'w'))
cli = subprocess.Popen([f'{BASE}/sbclient/sing-box', 'run', '-c', '/tmp/sbclient.json'], stderr=open('/tmp/sbclient.log', 'w'))
try:
    time.sleep(1.5)
    try:
        urllib.request.urlopen(urllib.request.Request(API + '/status', headers={'Authorization': 'Bearer wrong'}), timeout=5)
        check('auth rejects bad token', False)
    except urllib.error.HTTPError as e:
        check('auth rejects bad token', e.code == 401, str(e.code))
    r = call('POST', '/start', SERVER)
    check('start config', r.get('success'), r.get('msg', ''))
    check('status running', call('GET', '/status')['obj']['running'])
    time.sleep(1)
    for port, name in ((42001, 'anytls'), (42002, 'hysteria2'), (42003, 'tuic'), (42005, 'hysteria')):
        out = curl(port)
        check(f'{name} proxies traffic', out.startswith('ip='), out)
    stats = call('POST', '/stats')['obj'] or []
    users = {(s['tag'], s['direction']): s['traffic'] for s in stats if s['resource'] == 'user'}
    for u in ('alice', 'bob', 'carol', 'erin'):
        check(f'stats for {u}', users.get((u, True), 0) > 0 and users.get((u, False), 0) > 0,
              f"up={users.get((u, True))} down={users.get((u, False))}")
    check('stats drained', not any(s['resource'] == 'user' for s in (call('POST', '/stats')['obj'] or [])))

    # Hot swap anytls users: alice out, dave in.
    swapped = dict(ANYTLS, users=[{'name': 'dave', 'password': 'pw-dave'}])
    r = call('POST', '/inbound/users', swapped)
    check('hot user update', r.get('success') and r['obj']['hot'], json.dumps(r))
    check('removed user rejected', curl(42001) == 'FAILED')
    check('added user accepted', curl(42004).startswith('ip='))

    # Remove + re-add an inbound at runtime.
    check('remove inbound', call('POST', '/inbound/del', {'tag': 'in-tuic'}).get('success'))
    check('removed inbound unreachable', curl(42003) == 'FAILED')
    check('add inbound', call('POST', '/inbound/add', TUIC).get('success'))
    time.sleep(0.5)
    check('re-added inbound works', curl(42003).startswith('ip='))

    # Long-lived download, then kick; judged server-side since client buffers keep draining.
    for port, user in ((42002, 'bob'), (42004, 'dave')):
        dl = subprocess.Popen(['curl', '-s', '-o', '/dev/null', '-m', '25', '--limit-rate', '200K', '-x', f'socks5h://127.0.0.1:{port}',
                               'https://speed.cloudflare.com/__down?bytes=50000000'])
        time.sleep(4)
        sess = call('GET', '/sessions')['obj'] or []
        check(f'{user} session visible with source ip', any(s.get('user') == user and s.get('source') for s in sess),
              str([(s.get('user'), s.get('source'), s.get('domain')) for s in sess])[:200])
        call('POST', '/stats')
        k = call('POST', '/kick', {'user': user})
        time.sleep(2)
        call('POST', '/stats')
        time.sleep(4)
        after = sum(s['traffic'] for s in (call('POST', '/stats')['obj'] or []) if s['resource'] == 'user' and s['tag'] == user)
        left = [s for s in (call('GET', '/sessions')['obj'] or []) if s.get('user') == user]
        check(f'kick {user} stops server traffic', after == 0 and not left, f"closed={k['obj']['closed']} bytes_after={after} sessions_left={len(left)}")
        dl.kill()
    r = call('POST', '/start', {'inbounds': [{'type': 'anytls', 'tag': 'x', 'listen_port': 'bad'}]})
    check('bad config rejected', not r.get('success'), r.get('msg', '')[:120])
finally:
    cli.terminate(); srv.terminate()
    srv.wait(5); cli.wait(5)
print(open('/tmp/sbcore.log').read()[-1500:])
