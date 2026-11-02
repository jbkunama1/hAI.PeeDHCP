import importlib, tempfile, unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch
b = importlib.import_module('backend.app')
MAC = 'aa:bb:cc:dd:ee:ff'

class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        for key,value in [('DATA_DIR',tmp.name),('ADMIN_PIN','test-pin'),('_failures',{}),('REQUIRE_READ_AUTH',False),('_sid',None),('_sid_expires',0)]:
            p = patch.object(b,key,value); p.start(); self.addCleanup(p.stop)
        p = patch('requests.sessions.Session.request',side_effect=AssertionError('Live network forbidden')); p.start(); self.addCleanup(p.stop)
        self.c = b.app.test_client(); self.h = {'X-Admin-Token':b._signer.dumps('admin')}
    def test_empty_reset_body_rejected(self):
        self.assertEqual(self.c.post('/api/settings/reset',headers=self.h).status_code,400)
    def test_concurrent_notes(self):
        macs = ['aa:bb:cc:dd:ee:%02x'%i for i in range(20)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda mac:b.set_comment(mac,'note'),macs))
        self.assertEqual(set(b.read_json('meta.json',{})),set(macs))
    def test_concurrent_settings(self):
        def update(payload):
            with b.app.test_client() as c: return c.post('/api/settings',json=payload,headers=self.h).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(update,[{'title':'Concurrent'},{'theme':'light'}]))
        self.assertEqual(result,[200,200]); self.assertEqual(b.get_settings()['title'],'Concurrent'); self.assertEqual(b.get_settings()['theme'],'light')
    def test_single_sided_pool_validation(self):
        with patch.object(b,'dhcp_cfg',return_value={'start':'192.168.1.10','end':'192.168.1.100','router':'192.168.1.1'}), patch.object(b,'ph') as ph:
            r = self.c.post('/api/config',json={'DHCP_START':'192.168.1.200'},headers=self.h)
        self.assertEqual(r.status_code,400); ph.assert_not_called()
    def test_invalid_dns_prevents_dhcp_write(self):
        with patch.object(b,'dhcp_cfg',return_value={'start':'192.168.1.10','end':'192.168.1.100','router':'192.168.1.1'}), patch.object(b,'config_part',return_value={'upstreams':['1.1.1.1']}), patch.object(b,'ph') as ph:
            r = self.c.post('/api/config',json={'DHCP_END':'192.168.1.110','PIHOLE_DNS_1':'bad\nvalue'},headers=self.h)
        self.assertEqual(r.status_code,400); ph.assert_not_called()
    def test_auth_short_session_not_extended(self):
        response = Mock(); response.json.return_value = {'session':{'valid':True,'sid':'test','validity':5}}
        with patch.object(b.requests,'post',return_value=response), patch.object(b.time,'time',return_value=100):
            self.assertEqual(b.get_sid(),'test')
        self.assertLessEqual(b._sid_expires,105)
    def test_invalid_auth_session(self):
        response = Mock(); response.json.return_value = {'session':{'valid':False,'sid':'test','validity':100}}
        with patch.object(b.requests,'post',return_value=response): self.assertIsNone(b.get_sid())
    def test_bad_upstream_json(self):
        response = Mock(status_code=200,content=b'invalid'); response.json.side_effect = ValueError()
        with patch.object(b,'get_sid',return_value='test'), patch.object(b.requests,'get',return_value=response):
            data,error = b.ph('get','/stats/summary')
        self.assertIsNone(data); self.assertTrue(error)
    def test_login_limit_ignores_forwarded_header(self):
        for i in range(5):
            self.assertEqual(self.c.post('/api/admin/login',json={'pin':'wrong'},headers={'X-Forwarded-For':str(i)}).status_code,403)
        self.assertEqual(self.c.post('/api/admin/login',json={'pin':'wrong'},headers={'X-Forwarded-For':'new'}).status_code,429)
    def test_log_uses_dnsmasq_only(self):
        data = {'log':[{'timestamp':1,'message':'DHCPACK printer'},{'timestamp':2,'message':'query[A] example.org'}]}
        with patch.object(b,'ph',return_value=(data,None)) as ph: r = self.c.get('/api/log')
        self.assertEqual(r.status_code,200); self.assertEqual(len(r.get_json()['lines']),1); ph.assert_called_once_with('get','/logs/dnsmasq')
    def test_read_auth(self):
        with patch.object(b,'REQUIRE_READ_AUTH',True), patch.object(b,'get_leases',return_value=([],None)):
            self.assertEqual(self.c.get('/api/leases').status_code,401)
            self.assertEqual(self.c.get('/api/leases',headers=self.h).status_code,200)
    def test_empty_replace_backup(self):
        b.write_json('meta.json',{MAC:{'comment':'old'}})
        with patch.object(b,'read_hosts',return_value=([MAC+',192.168.1.42,printer'],None)), patch.object(b,'get_leases',return_value=([],None)), patch.object(b,'dhcp_cfg',return_value={'router':'192.168.1.1'}), patch.object(b,'write_hosts',return_value=None) as write:
            r = self.c.post('/api/import',json={'version':2,'mode':'replace','hosts':[]},headers=self.h)
        self.assertEqual(r.status_code,200); write.assert_called_once_with([]); self.assertEqual(b.read_json('meta.json',{}),{}); self.assertEqual(b.get_settings(),b.DEFAULTS)
    def test_restore_upstream_failure_keeps_local_data(self):
        b.write_json('meta.json',{MAC:{'comment':'keep'}})
        with patch.object(b,'read_hosts',return_value=([],None)), patch.object(b,'get_leases',return_value=([],None)), patch.object(b,'dhcp_cfg',return_value={'router':'192.168.1.1'}), patch.object(b,'write_hosts',return_value='offline'):
            r = self.c.post('/api/import',json={'hosts':[],'mode':'replace'},headers=self.h)
        self.assertEqual(r.status_code,502); self.assertEqual(b.read_json('meta.json',{})[MAC]['comment'],'keep'); self.assertIn('checkpoint',r.get_json())

if __name__ == '__main__': unittest.main()
