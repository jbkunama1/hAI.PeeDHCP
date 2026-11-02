import importlib, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
b = importlib.import_module('backend.app')
MAC = 'aa:bb:cc:dd:ee:ff'
NEW = 'aa:bb:cc:dd:ee:01'

class SafetyTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.root = t.name
        for k,v in [('DATA_DIR',t.name),('ADMIN_PIN','test-pin')]:
            p = patch.object(b,k,v); p.start(); self.addCleanup(p.stop)
        p = patch('requests.sessions.Session.request',side_effect=AssertionError('Live network forbidden')); p.start(); self.addCleanup(p.stop)
        self.c = b.app.test_client(); self.h = {'X-Admin-Token':b._signer.dumps('admin')}
    def test_lease_delete_uses_ip(self):
        with patch.object(b,'get_leases',return_value=([{'mac':MAC,'ip':'192.168.1.42'}],None)), patch.object(b,'ph',return_value=({},None)) as ph:
            r = self.c.delete('/api/lease/'+MAC,headers=self.h)
        self.assertEqual(r.status_code,200); ph.assert_called_once_with('delete','/dhcp/leases/192.168.1.42')
    def test_missing_lease_no_delete(self):
        with patch.object(b,'get_leases',return_value=([],None)), patch.object(b,'ph') as ph:
            r = self.c.delete('/api/lease/'+MAC,headers=self.h)
        self.assertEqual(r.status_code,404); ph.assert_not_called()
    def test_bad_json(self):
        for value in ([],None,'text',42):
            r = self.c.post('/api/static',json=value,headers=self.h); self.assertEqual(r.status_code,400)
    def test_failed_edit_does_not_predelete(self):
        hosts = [MAC+',192.168.1.42,printer,24h']
        with patch.object(b,'read_hosts',return_value=(hosts,None)), patch.object(b,'get_leases',return_value=([],None)), patch.object(b,'dhcp_cfg',return_value={'router':'192.168.1.1'}), patch.object(b,'write_hosts') as write:
            r = self.c.put('/api/static/'+MAC,json={'new_mac':NEW,'ip':'invalid'},headers=self.h)
        self.assertEqual(r.status_code,400); write.assert_not_called()
    def test_edit_preserves_extra(self):
        hosts = [MAC+',192.168.1.42,printer,24h','id:client,192.168.1.99']
        with patch.object(b,'read_hosts',return_value=(hosts,None)), patch.object(b,'get_leases',return_value=([],None)), patch.object(b,'dhcp_cfg',return_value={'router':'192.168.1.1'}), patch.object(b,'write_hosts',return_value=None) as write:
            r = self.c.put('/api/static/'+MAC,json={'new_mac':NEW,'ip':'192.168.1.43','hostname':'printer'},headers=self.h)
        self.assertEqual(r.status_code,200); write.assert_called_once_with([NEW+',192.168.1.43,printer,24h',hosts[1]])
    def test_corruption_not_overwritten(self):
        path = Path(self.root,'settings.json'); path.write_text('{broken')
        r = self.c.post('/api/settings',json={'title':'new'},headers=self.h)
        self.assertEqual(r.status_code,500); self.assertEqual(path.read_text(),'{broken')
    def test_merge_notes_and_raw_backup(self):
        b.write_json('meta.json',{MAC:{'comment':'keep'}})
        with patch.object(b,'read_hosts',return_value=([],None)), patch.object(b,'get_leases',return_value=([],None)), patch.object(b,'dhcp_cfg',return_value={'router':'192.168.1.1'}), patch.object(b,'write_hosts',return_value=None) as write:
            r = self.c.post('/api/import',json={'version':2,'hosts':['id:client,192.168.1.99'],'meta':{NEW:{'comment':'new'}}},headers=self.h)
        self.assertEqual(r.status_code,200); self.assertEqual(len(b.read_json('meta.json',{})),2); write.assert_called_once_with(['id:client,192.168.1.99'])
    def test_incomplete_backup_cannot_clear_hosts(self):
        with patch.object(b,'write_hosts') as write:
            r = self.c.post('/api/import',json={'mode':'replace'},headers=self.h)
        self.assertEqual(r.status_code,400); write.assert_not_called()
    def test_invalid_count(self):
        self.assertEqual(self.c.get('/api/free_ips?count=no').status_code,400)
    def test_local_liveness(self):
        with patch.object(b,'ph',return_value=(None,'offline')):
            self.assertEqual(self.c.get('/api/livez').status_code,200)
            self.assertEqual(self.c.get('/api/health').status_code,502)
    def test_unknown_netmask_requires_range(self):
        with patch.object(b,'dhcp_cfg',return_value={'router':'192.168.1.1','netmask':'0.0.0.0'}):
            self.assertEqual(self.c.get('/api/free_ips').status_code,400)
    def test_default_tls_verification(self):
        self.assertIs(b.PIHOLE_VERIFY,True)

if __name__ == '__main__': unittest.main()
