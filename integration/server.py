"""Scoped Happ routing delivery in front of an existing 3x-ui subscription.

Only the configured subscription is proxied here. Clients keep the original
3x-ui response body; this adapter adds its routing profile HTTP header.
"""
import base64
import copy
import datetime
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 200_000
MAX_RULES = 3000
LOCK = threading.RLock()


def normalize_rule(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError('Недопустимое правило')
    value = value.strip()
    if not value.lower().startswith('regexp:'):
        value = value.rstrip('\\').rstrip()
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Пустое правило или управляющий символ')
    if value.startswith(('http://', 'https://')):
        value = urllib.parse.urlsplit(value).hostname or ''
    if ':' in value:
        prefix, value = value.split(':', 1)
        prefix = prefix.lower()
    else:
        prefix = 'domain'
    if prefix in ('domain', 'full'):
        value = value.removeprefix('*.').rstrip('.').lower()
        value = value.encode('idna').decode('ascii')
        if len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
            raise ValueError('Некорректный домен')
    elif prefix == 'geosite':
        if not re.fullmatch(r'[a-zA-Z0-9_@!.-]+', value):
            raise ValueError('Некорректная категория GeoSite')
    elif prefix not in ('keyword', 'regexp') or not value:
        raise ValueError('Неподдерживаемый тип правила')
    return prefix + ':' + value


def make_profile(template, rules, allowed_tags=None):
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_RULES:
        raise ValueError('Нужен непустой список исключений')
    normalized = list(dict.fromkeys(normalize_rule(x) for x in rules))
    if allowed_tags is not None:
        for rule in normalized:
            if rule.startswith('geosite:') and rule.split(':', 1)[1].split('@', 1)[0] not in allowed_tags:
                raise ValueError('Категория GeoSite отсутствует в используемой базе')
    profile = copy.deepcopy(template)
    profile['Name'] = 'My Cloud Direct'
    profile['DirectSites'] = normalized
    return profile


def atomic_save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.profile-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, separators=(',', ':'))
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def profile_header(profile):
    data = json.dumps(profile, ensure_ascii=False, separators=(',', ':')).encode()
    return 'happ://routing/onadd/' + base64.b64encode(data).decode()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, config):
        self.config = config
        self.state_path = Path(config['state_path'])
        if self.state_path.exists():
            state = json.loads(self.state_path.read_text())
            previous_timestamp = state['profile'].get('LastUpdated', int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
            state['profile'] = make_profile(config['template'], state['profile']['DirectSites'], config.get('allowed_geosite_tags'))
            state['profile']['LastUpdated'] = previous_timestamp
        else:
            state = {'profile': make_profile(config['template'], config['initial_rules'], config.get('allowed_geosite_tags')), 'revision': 1,
                     'updatedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
            state['profile']['LastUpdated'] = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
            atomic_save(self.state_path, state)
        self.state = state
        super().__init__(address, Handler)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'HappDirect'

    def log_message(self, *args):
        pass  # Never log authorization headers or private subscription URLs.

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def cors(self):
        if self.headers.get('Origin') == self.server.config['allowed_origin']:
            self.send_header('Access-Control-Allow-Origin', self.server.config['allowed_origin'])
            self.send_header('Vary', 'Origin')

    def json_response(self, status, value):
        data = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
        self.send_response(status)
        self.cors()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        origin = self.headers.get('Origin')
        if origin and origin != self.server.config['allowed_origin']:
            self.json_response(403, {'error': 'Запрещённый источник запроса'})
            return False
        expected = 'Bearer ' + self.server.config['api_key']
        if not hmac.compare_digest(self.headers.get('Authorization', ''), expected):
            self.json_response(401, {'error': 'Нужен ключ подключения подписки'})
            return False
        return True

    def state_response(self):
        with LOCK:
            state = copy.deepcopy(self.server.state)
        return {**state, 'subscriptionName': 'vless.ugol.red',
                'subscriptionUrl': self.server.config['subscription_url'],
                'count': len(state['profile']['DirectSites'])}

    def do_OPTIONS(self):
        if self.path != '/profile' or self.headers.get('Origin') != self.server.config['allowed_origin']:
            self.json_response(403, {'error': 'Запрос запрещён'})
            return
        self.send_response(204)
        self.cors()
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        if self.path == '/healthz':
            self.json_response(200, {'ok': True})
        elif self.path == '/profile':
            if self.authorized():
                self.json_response(200, self.state_response())
        elif self.path == '/subscription':
            self.subscription()
        else:
            self.json_response(404, {'error': 'Не найдено'})

    def do_POST(self):
        if self.path != '/profile':
            self.json_response(404, {'error': 'Не найдено'})
            return
        if not self.authorized():
            return
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 < length <= MAX_BODY:
                self.json_response(413, {'error': 'Слишком большой список'})
                return
            if self.headers.get_content_type() != 'application/json':
                raise ValueError('Ожидается JSON')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError('Ожидается объект')
            profile = make_profile(self.server.config['template'], body.get('directSites'), self.server.config.get('allowed_geosite_tags'))
            with LOCK:
                if body.get('expectedRevision') != self.server.state['revision']:
                    self.json_response(409, {'error': 'Список обновлён в другом браузере. Перезагрузите страницу, чтобы сохранить новые правила.'})
                    return
                profile['LastUpdated'] = max(int(datetime.datetime.now(datetime.timezone.utc).timestamp()), self.server.state['profile'].get('LastUpdated', 0) + 1)
                state = {'profile': profile, 'revision': self.server.state['revision'] + 1,
                         'updatedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
                atomic_save(self.server.state_path, state)
                self.server.state = state
        except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
            self.json_response(400, {'error': 'Некорректный список исключений'})
            return
        except OSError:
            self.json_response(503, {'error': 'Список не удалось сохранить. Прежние правила сохранены.'})
            return
        self.json_response(200, self.state_response())

    def subscription(self):
        config = self.server.config
        # This URL is configured by root and always targets the local 3x-ui port.
        headers = {'Host': config['upstream_host'],
                   'User-Agent': self.headers.get('User-Agent', 'Happ'),
                   'Accept': self.headers.get('Accept', '*/*')}
        request = urllib.request.Request(config['upstream_url'], headers=headers)
        try:
            # Local HTTPS listener uses a certificate for its public hostname.
            with urllib.request.urlopen(request, timeout=10, context=ssl._create_unverified_context()) as upstream:
                body = upstream.read(2_000_001)
                if len(body) > 2_000_000:
                    raise ValueError('Upstream response too large')
                response_headers = list(upstream.headers.items())
                status = upstream.status
        except (OSError, ValueError, urllib.error.URLError):
            self.json_response(502, {'error': 'Подписка временно недоступна'})
            return
        with LOCK:
            routing = profile_header(self.server.state['profile'])
        self.send_response(status)
        blocked = {'content-length', 'connection', 'transfer-encoding', 'routing', 'routing-enable', 'server', 'date', 'cache-control'}
        for key, value in response_headers:
            if key.lower() not in blocked:
                self.send_header(key, value)
        self.send_header('Routing', routing)
        self.send_header('Routing-Enable', 'true')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    credential_dir = os.environ.get('CREDENTIALS_DIRECTORY', '/etc/happ-direct')
    config = json.loads((Path(credential_dir) / 'config.json').read_text())
    Server(('127.0.0.1', config.get('port', 18766)), config).serve_forever()
