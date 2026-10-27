#!/usr/bin/env python3
# Usage: e2e_singbox_panel.py <panelBaseUrl> <adminPassword>; needs a running panel with sbcore in bin/,
# the official sing-box client at /root/s3x-test/sbclient/sing-box and a test cert in /root/s3x-test/cert.
# End-to-end: sing-box inbound managed purely through the 2.6.2 panel API.
import http.cookiejar, json, os, subprocess, sys, time, urllib.parse, urllib.request

base, pw = sys.argv[1:3]
BASE = '/root/s3x-test'
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def post(p, d=None):
    with op.open(base + p, urllib.parse.urlencode(d or {}).encode(), timeout=30) as r:
        return json.loads(r.read() or b'{}')


def check(label, cond, detail=''):
    print(f"{'PASS' if cond else 'FAIL'}  {label}  {detail}")


def client(email, password, enable=True):
    return {'email': email, 'password': password, 'enable': enable, 'limitIp': 0, 'totalGB': 0, 'expiryTime': 0,
            'tgId': '', 'subId': email + 'sub', 'comment': '', 'reset': 0}


def sbcore_pid():
    r = subprocess.run(['pgrep', '-f', 'sbcore-linux-amd64'], capture_output=True, text=True)
    return r.stdout.strip()


def curl(port):
    r = subprocess.run(['curl', '-s', '-m', '10', '-x', f'socks5h://127.0.0.1:{port}', 'https://www.cloudflare.com/cdn-cgi/trace'],
                       capture_output=True, text=True)
    return next((l for l in r.stdout.splitlines() if l.startswith('ip=')), 'FAILED')


ctls = {'enabled': True, 'insecure': True, 'server_name': 'test.example.com'}
CLIENT = {
    'log': {'level': 'error'},
    'inbounds': [{'type': 'mixed', 'tag': f'm{i}', 'listen': '127.0.0.1', 'listen_port': 43000 + i} for i in (1, 2)],
    'outbounds': [
        {'type': 'anytls', 'tag': 'o1', 'server': '127.0.0.1', 'server_port': 41101, 'password': 'pw-alice', 'tls': ctls},
        {'type': 'anytls', 'tag': 'o2', 'server': '127.0.0.1', 'server_port': 41101, 'password': 'pw-bob', 'tls': ctls},
    ],
    'route': {'rules': [{'inbound': [f'm{i}'], 'outbound': f'o{i}'} for i in (1, 2)]},
}
json.dump(CLIENT, open('/tmp/e2e-client.json', 'w'))
cli = subprocess.Popen([f'{BASE}/sbclient/sing-box', 'run', '-c', '/tmp/e2e-client.json'], stderr=subprocess.DEVNULL)

try:
    post('/login', {'username': 'admin', 'password': pw})
    check('sbcore idle without sing-box inbounds', sbcore_pid() == '')
    stream = {'security': 'tls', 'tlsSettings': {'serverName': 'test.example.com', 'alpn': ['h2', 'http/1.1'],
              'certificates': [{'certificateFile': f'{BASE}/cert/c.crt', 'keyFile': f'{BASE}/cert/c.key'}]}}
    add = post('/panel/inbound/add', {
        'up': 0, 'down': 0, 'total': 0, 'remark': 'e2e-anytls', 'enable': True, 'expiryTime': 0, 'listen': '', 'port': 41101,
        'protocol': 'anytls', 'settings': json.dumps({'clients': [client('at-alice', 'pw-alice')]}),
        'streamSettings': json.dumps(stream), 'sniffing': '{}', 'allocate': '{}'})
    check('add anytls inbound', add.get('success'), add.get('msg'))
    ib = add['obj']
    check('sing-box tag prefix', ib['tag'] == 'sb-inbound-41101', ib['tag'])
    time.sleep(2)
    check('sbcore started on demand', sbcore_pid() != '')
    cfg = post('/server/getConfigJson')['obj']
    tags = [i.get('tag') for i in cfg.get('inbounds', [])]
    check('xray has bridge, not the sing-box inbound', 'sbcore-bridge' in tags and ib['tag'] not in tags, str(tags))
    out = curl(43001)
    check('client traffic flows through sbcore -> xray', out.startswith('ip='), out)

    time.sleep(11)
    lst = post('/panel/inbound/list')['obj']
    me = next(i for i in lst if i['id'] == ib['id'])
    st = next(c for c in me['clientStats'] if c['email'] == 'at-alice')
    check('client traffic recorded in panel', st['up'] > 0 and st['down'] > 0, f"up={st['up']} down={st['down']}")
    check('inbound traffic recorded in panel', me['up'] > 0 and me['down'] > 0, f"up={me['up']} down={me['down']}")

    r = post('/panel/inbound/addClient', {'id': ib['id'], 'settings': json.dumps({'clients': [client('at-bob', 'pw-bob')]})})
    check('add client', r.get('success'), r.get('msg'))
    time.sleep(1.5)
    pid_before = sbcore_pid()
    check('added client connects', curl(43002).startswith('ip='))

    r = post('/panel/inbound/updateClient/at-alice', {'id': ib['id'], 'settings': json.dumps({'clients': [client('at-alice', 'pw-alice', enable=False)]})})
    check('disable client', r.get('success'), r.get('msg'))
    time.sleep(1.5)
    check('disabled client rejected', curl(43001) == 'FAILED')
    check('other client unaffected', curl(43002).startswith('ip='))
    check('user changes are hot (same sbcore process)', sbcore_pid() == pid_before)

    r = post(f"/panel/inbound/{ib['id']}/delClient/at-bob")
    check('delete client', r.get('success'), r.get('msg'))
    time.sleep(1.5)
    check('deleted client rejected', curl(43002) == 'FAILED')

    r = post(f"/panel/inbound/del/{ib['id']}")
    check('delete inbound', r.get('success'), r.get('msg'))
    time.sleep(2)
    check('sbcore stopped when last sing-box inbound is gone', sbcore_pid() == '')
    time.sleep(31)
    cfg = post('/server/getConfigJson')['obj']
    check('bridge removed from xray after restart window', 'sbcore-bridge' not in [i.get('tag') for i in cfg.get('inbounds', [])])
finally:
    cli.terminate()
