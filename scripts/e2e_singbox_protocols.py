#!/usr/bin/env python3
# Usage: e2e_singbox_protocols.py <panelBaseUrl> <adminPassword>; same setup as e2e_singbox_panel.py, plus
# libcronet.so from the sing-box release next to the client for the naive outbound. The test cert needs a
# SAN and at most 200 days validity, or cronet rejects it.
# Real traffic through every sing-box protocol, configured only via the panel
# API with the same JSON the panel UI produces.
import http.cookiejar, json, subprocess, sys, time, urllib.parse, urllib.request

base, pw = sys.argv[1:3]
BASE = '/root/s3x-test'
SNI = 'test.example.com'
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
fails = 0


def post(p, d=None):
    with op.open(base + p, urllib.parse.urlencode(d or {}).encode(), timeout=30) as r:
        return json.loads(r.read() or b'{}')


def check(label, cond, detail=''):
    global fails
    fails += not cond
    print(f"{'PASS' if cond else 'FAIL'}  {label}  {detail}")


def client(email, password, cid=None):
    c = {'email': email, 'password': password, 'enable': True, 'limitIp': 0, 'totalGB': 0, 'expiryTime': 0,
         'tgId': '', 'subId': email + 'sub', 'comment': '', 'reset': 0}
    if cid:
        c['id'] = cid
    return c


def tls_stream(alpn):
    return {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
        'serverName': SNI, 'alpn': alpn,
        'certificates': [{'certificateFile': f'{BASE}/cert/c.crt', 'keyFile': f'{BASE}/cert/c.key'}]}}


UUID = '6f1d8f4e-3c1b-4a8e-9f57-2b4a7c9d0e11'
SSPW = 'kQ2b8N1rT5vX7zA3cE6gHw=='  # 16 bytes, 2022-blake3-aes-128-gcm
CASES = [
    # protocol, port, settings, stream, client outbound
    ('anytls', 42201, {}, tls_stream(['h2', 'http/1.1']),
     {'type': 'anytls', 'password': 'pw-anytls'}),
    ('hysteria2', 42202, {'up_mbps': 0, 'down_mbps': 0, 'obfs': {'type': 'salamander', 'password': 'obfs-pw'}},
     tls_stream(['h3']), {'type': 'hysteria2', 'password': 'pw-hysteria2', 'obfs': {'type': 'salamander', 'password': 'obfs-pw'}}),
    ('tuic', 42203, {'congestion_control': 'bbr', 'zero_rtt_handshake': False, 'auth_timeout': '3s', 'heartbeat': '10s'},
     tls_stream(['h3']), {'type': 'tuic', 'uuid': UUID, 'password': 'pw-tuic', 'congestion_control': 'bbr'}),
    ('hysteria', 42204, {'up_mbps': 100, 'down_mbps': 100}, tls_stream([]),
     {'type': 'hysteria', 'auth_str': 'pw-hysteria', 'up_mbps': 100, 'down_mbps': 100}),
    ('naive', 42205, {}, tls_stream(['h2', 'http/1.1']),
     {'type': 'naive', 'username': 'naive-user', 'password': 'pw-naive'}),
    ('shadowtls', 42206, {'version': 3, 'handshake': {'server': 'www.microsoft.com', 'server_port': 443}, 'strict_mode': True,
                          'shadowsocks': {'method': '2022-blake3-aes-128-gcm', 'password': SSPW}}, None,
     {'type': 'shadowtls', 'version': 3, 'password': 'pw-shadowtls'}),
    ('snell', 42207, {'version': 5, 'psk': 'snell-psk-0123456789', 'obfs_mode': 'none'}, None,
     {'type': 'snell', 'version': 4, 'psk': 'snell-psk-0123456789', 'userkey': 'pw-snell'}),
]

post('/login', {'username': 'admin', 'password': pw})
for ib in post('/panel/inbound/list')['obj']:
    if ib['remark'].startswith(('e2e-', 'ui-')):
        post(f"/panel/inbound/del/{ib['id']}")

outbounds, inbounds, rules = [], [], []
for i, (proto, port, settings, stream, out) in enumerate(CASES):
    email = 'naive-user' if proto == 'naive' else f'{proto}-user'
    settings = dict(settings, clients=[client(email, out.get('password') or out.get('auth_str') or out.get('userkey'),
                                              UUID if proto == 'tuic' else None)])
    if proto == 'shadowtls':
        settings['clients'][0]['password'] = 'pw-shadowtls'
    if proto == 'snell':
        settings['clients'][0]['password'] = 'pw-snell'
    r = post('/panel/inbound/add', {
        'up': 0, 'down': 0, 'total': 0, 'remark': f'e2e-{proto}', 'enable': True, 'expiryTime': 0, 'listen': '',
        'port': port, 'protocol': proto, 'settings': json.dumps(settings),
        'streamSettings': json.dumps(stream) if stream else '', 'sniffing': '{}', 'allocate': '{}'})
    check(f'add {proto}', r.get('success'), r.get('msg', ''))

    out = dict(out, tag=f'o-{proto}', server='127.0.0.1', server_port=port)
    if stream:
        alpn = {'hysteria2': ['h3'], 'tuic': ['h3'], 'hysteria': ['hysteria']}.get(proto)
        out['tls'] = {'enabled': True, 'server_name': SNI, 'insecure': True, **({'alpn': alpn} if alpn else {})}
        if proto == 'naive':  # cronet ignores insecure; trust the test cert instead
            out['tls'] = {'enabled': True, 'server_name': SNI, 'certificate_path': f'{BASE}/cert/c.crt'}
    if proto == 'shadowtls':
        out['tls'] = {'enabled': True, 'server_name': 'www.microsoft.com'}
        outbounds.append({'type': 'shadowsocks', 'tag': 'o-shadowtls-ss', 'method': '2022-blake3-aes-128-gcm',
                          'password': SSPW, 'detour': 'o-shadowtls'})
        route_to = 'o-shadowtls-ss'
    else:
        route_to = out['tag']
    outbounds.append(out)
    inbounds.append({'type': 'mixed', 'tag': f'm-{proto}', 'listen': '127.0.0.1', 'listen_port': 43100 + i})
    rules.append({'inbound': [f'm-{proto}'], 'outbound': route_to})

json.dump({'log': {'level': 'warn'}, 'inbounds': inbounds, 'outbounds': outbounds, 'route': {'rules': rules}},
          open('/tmp/e2e-proto-client.json', 'w'))
time.sleep(3)
cli = subprocess.Popen([f'{BASE}/sbclient/sing-box', 'run', '-c', '/tmp/e2e-proto-client.json'],
                       stderr=open('/tmp/e2e-proto-client.log', 'w'))
time.sleep(2)
try:
    for i, (proto, *_rest) in enumerate(CASES):
        r = subprocess.run(['curl', '-s', '-m', '12', '-x', f'socks5h://127.0.0.1:{43100 + i}',
                            'https://www.cloudflare.com/cdn-cgi/trace'], capture_output=True, text=True)
        ip = next((l for l in r.stdout.splitlines() if l.startswith('ip=')), 'FAILED')
        check(f'traffic via {proto}', ip.startswith('ip='), ip)
    time.sleep(11)
    lst = {i['remark']: i for i in post('/panel/inbound/list')['obj']}
    for proto, *_rest in CASES:
        ib = lst[f'e2e-{proto}']
        st = ib['clientStats'][0] if ib['clientStats'] else {'up': 0, 'down': 0}
        check(f'{proto} traffic accounted', ib['up'] > 0 and st['down'] > 0,
              f"inbound up={ib['up']} down={ib['down']} client up={st['up']} down={st['down']}")
finally:
    cli.terminate()
print('client log:', open('/tmp/e2e-proto-client.log').read()[-1500:])
sys.exit(1 if fails else 0)
