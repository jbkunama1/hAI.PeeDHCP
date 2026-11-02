import importlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

b = importlib.import_module('backend.app')
MAC = 'aa:bb:cc:dd:ee:ff'


class BackendContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name, value in [('DATA_DIR', self.tmp.name), ('ADMIN_PIN', 'test-pin'), ('_sid', None), ('_sid_expires', 0)]:
            p = patch.object(b, name, value)
            p.start()
            self.addCleanup(p.stop)
        network = patch('requests.sessions.Session.request', side_effect=AssertionError('Real network disabled in tests'))
        network.start()
        self.addCleanup(network.stop)
        self.client = b.app.test_client()
        self.headers = {'X-Admin-Token': b._signer.dumps('admin')}

    def test_normalization(self):
        self.assertEqual(b.norm_mac('AABBCCDDEEFF'), MAC)
        self.assertEqual(b.valid_ip('192.168.1.42'), '192.168.1.42')
        self.assertIsNone(b.valid_ip('999.1.1.1'))

    def test_admin_token_required(self):
        self.assertEqual(self.client.post('/api/settings', json={'title': 'test'}).status_code, 401)
        self.assertEqual(self.client.post('/api/settings', json={}, headers={'X-Admin-Token': 'tampered'}).status_code, 401)

    def test_login_token_contract(self):
        response = self.client.post('/api/admin/login', json={'pin': 'test-pin'})
        self.assertEqual(response.status_code, 200)
        token = response.get_json()['token']
        response = self.client.get('/api/settings', headers={'X-Admin-Token': token})
        self.assertTrue(response.get_json()['is_admin'])

    def test_settings_roundtrip(self):
        response = self.client.post('/api/settings', json={'title': 'Mein Netz', 'theme': 'light'}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = self.client.get('/api/settings').get_json()
        self.assertEqual(data['settings']['title'], 'Mein Netz')
        self.assertEqual(data['settings']['theme'], 'light')
        self.assertFalse(data['is_admin'])
        self.assertEqual(json.loads(Path(self.tmp.name, 'settings.json').read_text())['title'], 'Mein Netz')

    def test_settings_reset(self):
        response = self.client.post('/api/settings/reset', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['settings'], b.DEFAULTS)

    def test_notes_roundtrip(self):
        response = self.client.post('/api/meta/' + MAC, json={'comment': 'Drucker'}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b.read_json('meta.json', {})[MAC]['comment'], 'Drucker')

    def test_combined_device_contract(self):
        lease = {'mac': MAC, 'ip': '192.168.1.42', 'hostname': 'printer', 'expires': 123}
        with patch.object(b, 'get_leases', return_value=([lease], None)), patch.object(b, 'read_hosts', return_value=([MAC + ',192.168.1.42,printer'], None)):
            response = self.client.get('/api/all_devices')
        self.assertEqual(response.status_code, 200)
        devices = response.get_json()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['type'], 'static+active')
        self.assertEqual(devices[0]['static_ip'], '192.168.1.42')

    def test_lease_schema_mapping(self):
        with patch.object(b, 'ph', return_value=({'leases': [{'hwaddr': MAC.upper(), 'ip': '192.168.1.42', 'name': '*', 'expires': 123}]}, None)):
            leases, error = b.get_leases()
        self.assertIsNone(error)
        self.assertEqual(leases, [{'mac': MAC, 'ip': '192.168.1.42', 'hostname': '', 'expires': 123}])

    def test_upstream_failure_is_502(self):
        with patch.object(b, 'ph', return_value=(None, 'unavailable')):
            response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()['status'], 'pihole_unreachable')

    def test_export_preserves_raw_hosts(self):
        raw = ['id:client,192.168.1.43', MAC + ',192.168.1.42,printer,24h']
        with patch.object(b, 'read_hosts', return_value=(raw, None)):
            response = self.client.get('/api/export')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['hosts'], raw)
        self.assertIn('settings', response.get_json())
        self.assertIn('meta', response.get_json())

    def test_invalid_static_never_writes(self):
        with patch.object(b, 'read_hosts', return_value=([], None)), patch.object(b, 'get_leases', return_value=([], None)), patch.object(b, 'dhcp_cfg', return_value={'router': '192.168.1.1'}), patch.object(b, 'write_hosts') as write:
            response = self.client.post('/api/static', json={'mac': MAC, 'ip': 'invalid'}, headers=self.headers)
        self.assertEqual(response.status_code, 400)
        write.assert_not_called()

    def test_session_retry_after_401(self):
        unauthorized = Mock(status_code=401)
        success = Mock(status_code=200, content=b'{}')
        success.json.return_value = {'ok': True}
        with patch.object(b, 'get_sid', side_effect=['first', 'second']) as sid, patch.object(b.requests, 'get', side_effect=[unauthorized, success]) as get:
            data, error = b.ph('get', '/stats/summary')
        self.assertIsNone(error)
        self.assertTrue(data['ok'])
        self.assertEqual(get.call_count, 2)
        self.assertEqual(sid.call_args_list[1].kwargs, {'force': True})


if __name__ == '__main__':
    unittest.main()
