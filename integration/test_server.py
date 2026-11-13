import base64
import copy
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from server import Server, make_profile


class FakeUpstream:
    status = 200
    headers = {'Content-Type': 'text/plain', 'Subscription-Userinfo': 'upload=0;download=1;total=0;expire=0',
               'Routing': 'old-profile', 'Routing-Enable': 'false'}
    body = base64.b64encode(b'vless://test-credential@example.invalid:443?type=ws#test')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, size):
        return self.body


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = {
            'api_key': 'test-key', 'allowed_origin': 'https://dem36rus.github.io',
            'template': {'Name': 'My Cloud Direct', 'GlobalProxy': True, 'DirectIp': ['geoip:ru']},
            'initial_rules': ['domain:max.ru'],
            'state_path': str(Path(self.temp.name) / 'profile.json'),
            'subscription_url': 'https://example.invalid/private-subscription',
            'upstream_url': 'https://127.0.0.1:12345/private-subscription',
            'upstream_host': 'example.invalid',
        }
        self.server = Server(('127.0.0.1', 0), self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.temp.cleanup()

    def request(self, method, path='/profile', data=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        connection.request(method, path, json.dumps(data) if data is not None else None,
                           headers if headers is not None else {'Authorization': 'Bearer test-key', 'Content-Type': 'application/json',
                                       'Origin': self.config['allowed_origin']})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_unauthorized_cors_and_invalid_input_leave_state_unchanged(self):
        original = Path(self.config['state_path']).read_bytes()
        self.assertEqual(self.request('POST', data={'directSites': ['domain:mosenergosbyt.ru']}, headers={})[0], 401)
        status, headers, _ = self.request('OPTIONS', headers={'Origin': self.config['allowed_origin']})
        self.assertEqual(status, 204)
        self.assertEqual(headers['Access-Control-Allow-Origin'], self.config['allowed_origin'])
        self.assertEqual(self.request('GET', headers={'Authorization': 'Bearer test-key', 'Origin': 'https://untrusted.invalid'})[0], 403)
        self.assertEqual(self.request('POST', data={'directSites': ['domain:bad\nheader'], 'expectedRevision': 1})[0], 400)
        self.assertEqual(Path(self.config['state_path']).read_bytes(), original)

    def test_update_revision_conflict_persistence_and_native_subscription_header(self):
        status, _, body = self.request('POST', data={'directSites': ['domain:mosenergosbyt.ru', 'domain:мвд.рф', 'domain:max.ru'], 'expectedRevision': 1})
        self.assertEqual(status, 200)
        state = json.loads(body)
        self.assertEqual(state['revision'], 2)
        self.assertIn('domain:xn--b1aew.xn--p1ai', state['profile']['DirectSites'])
        self.assertEqual(self.request('POST', data={'directSites': ['domain:other.invalid'], 'expectedRevision': 1})[0], 409)
        with patch('server.urllib.request.urlopen', return_value=FakeUpstream()):
            status, headers, body = self.request('GET', '/subscription')
        self.assertEqual(status, 200)
        self.assertEqual(body, FakeUpstream.body)
        self.assertEqual(headers['Routing-Enable'], 'true')
        payload = headers['Routing'].split('happ://routing/onadd/')[1]
        profile = json.loads(base64.b64decode(payload))
        self.assertEqual(profile['Name'], 'My Cloud Direct')
        self.assertIn('domain:mosenergosbyt.ru', profile['DirectSites'])
        self.assertEqual(profile['DirectIp'], ['geoip:ru'])
        self.assertEqual(json.loads(Path(self.config['state_path']).read_text())['profile'], profile)

    def test_geosite_validation_and_pasted_line_continuations(self):
        profile = make_profile(self.config['template'], ['geosite:yandex' + chr(92), 'geosite:category-bank-ru'], ['yandex', 'category-bank-ru'])
        self.assertEqual(profile['DirectSites'], ['geosite:yandex', 'geosite:category-bank-ru'])
        with self.assertRaises(ValueError):
            make_profile(self.config['template'], ['geosite:nonexistent-category'], ['yandex'])

    def test_upstream_failure_does_not_return_a_fake_success(self):
        with patch('server.urllib.request.urlopen', side_effect=OSError('upstream unavailable')):
            self.assertEqual(self.request('GET', '/subscription')[0], 502)


if __name__ == '__main__':
    unittest.main()
