import sys,unittest,uuid,json,os
from pathlib import Path
from datetime import datetime,timezone,timedelta
from unittest.mock import patch
root=Path(__file__).resolve().parent
sys.path[:0]=[str(root.parent/'defender/testdeps'),str(root),os.getenv('NETCHECKER_TEST_SOURCE','D:/00.ai_project/NetChecker')]
from test_netchecker import Tests
import server
class Actions(unittest.TestCase):
 setUp_base=Tests.setUp
 enroll=Tests.enroll
 def setUp(self):
  self.setUp_base();server.attempts.clear()
  with server.db() as c:
   for t in ('defender_snapshots','defender_events','defender_reviews','defender_inventory','defender_actions'):c.execute('DELETE FROM '+t)
  self.device=self.enroll();self.token={'Authorization':'Bearer '+self.device['token']}
 def reset_budget(self):server.attempts.clear()
 def inventory(self):
  uid=str(uuid.uuid4());value={'observed_at':server.now(),'status':'available','updates':[{'id':uid,'revision':1,'title':'Security Update Test','kb':['1234567'],'reboot_may_be_needed':True}],'os_build':'test','firewall_enabled':True}
  r=self.client.post('/api/defender/inventory',json=value,headers=self.token);self.assertEqual(r.status_code,200,r.text);return uid
 def proposal(self,kind='update_install',target=None):
  target=target or self.inventory();r=self.client.post('/api/defender/'+self.device['id']+'/actions',json={'kind':kind,'target':target,'reason':'reviewed evidence and impact'},auth=self.auth,headers=self.headers);self.assertEqual(r.status_code,200,r.text);return r.json()['id']
 def approve(self,aid,backup=True):return self.client.post('/api/defender/actions/'+aid+'/approve',json={'target_device':self.device['id'],'backup_confirmed':backup,'impact_confirmed':True,'not_before':server.now()},auth=self.auth,headers=self.headers)
 def claim(self):self.reset_budget();return self.client.post('/api/defender/actions/claim',headers=self.token)
 def test_approval_backup_and_device_scope(self):
  aid=self.proposal();self.assertIsNone(self.claim().json()['action'])
  self.assertEqual(self.approve(aid,False).status_code,422)
  self.assertEqual(self.approve(aid).status_code,200)
  other=self.enroll();self.reset_budget();self.assertIsNone(self.client.post('/api/defender/actions/claim',headers={'Authorization':'Bearer '+other['token']}).json()['action'])
  action=self.claim().json()['action'];self.assertEqual(action['id'],aid);self.assertIsNone(self.claim().json()['action'])
  self.assertEqual(self.client.post('/api/defender/actions/'+aid+'/result',headers=self.token,json={'claim':'x'*48,'success':True,'verified':True,'detail':'fake'}).status_code,403)
  self.reset_budget();result={'claim':action['claim'],'success':True,'verified':False,'reboot_required':True,'detail':'installed; reboot pending'}
  r=self.client.post('/api/defender/actions/'+aid+'/result',headers=self.token,json=result);self.assertEqual(r.json()['status'],'verification_needed')
  self.assertEqual(self.client.post('/api/defender/actions/'+aid+'/recheck',auth=self.auth,headers=self.headers).status_code,200)
  check=self.claim().json()['action'];self.assertEqual(check['kind'],'verify_action')
  r=self.client.post('/api/defender/actions/'+check['id']+'/result',headers=self.token,json={'claim':check['claim'],'success':True,'verified':True,'detail':'installed; reboot clear'});self.assertEqual(r.json()['status'],'verified')
  with server.db() as c:self.assertEqual(c.execute('SELECT status FROM defender_actions WHERE id=?',(aid,)).fetchone()[0],'verified')
 def test_block_guard_and_expiry_cancel(self):
  for ip in ('10.0.0.5','127.0.0.1','8.8.8.8','1.1.1.1;whoami'):
   r=self.client.post('/api/defender/'+self.device['id']+'/actions',auth=self.auth,headers=self.headers,json={'kind':'firewall_block','target':ip,'reason':'reviewed evidence'});self.assertIn(r.status_code,(422,409))
  with server.db() as c:c.execute('INSERT INTO defender_events VALUES(?,?,?,?,?,?)',(self.device['id'],'Security','123',server.now(),4625,'8.8.8.8'))
  aid=self.proposal('firewall_block','8.8.8.8');self.assertEqual(self.approve(aid).status_code,200)
  with server.db() as c:c.execute('UPDATE defender_actions SET expires=? WHERE id=?',((datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat(),aid))
  self.assertIsNone(self.claim().json()['action'])
  aid=self.proposal();r=self.client.post('/api/defender/actions/'+aid+'/cancel',auth=self.auth,headers=self.headers,json={'reason':'maintenance postponed'});self.assertEqual(r.status_code,200);self.assertEqual(self.approve(aid).status_code,409)
 def test_inventory_validation_and_revoke(self):
  self.assertEqual(self.client.get('/api/defender/identity').status_code,401)
  self.assertEqual(self.client.get('/api/defender/identity',headers=self.token).status_code,200)
  self.assertEqual(self.client.post('/api/defender/inventory',json={'observed_at':server.now(),'status':'available','updates':[]}).status_code,401)
  self.assertEqual(self.client.get('/api/defender/'+self.device['id']+'/actions').status_code,401)
  aid=self.proposal();self.approve(aid);self.client.delete('/api/devices/'+self.device['id'],auth=self.auth,headers=self.headers);self.assertEqual(self.claim().status_code,401);self.reset_budget();self.assertEqual(self.client.get('/api/defender/identity',headers=self.token).status_code,401)
 def test_unknown_action_never_retries_but_read_recheck_allowed(self):
  aid=self.proposal();self.approve(aid);self.claim()
  with server.db() as c:c.execute('UPDATE defender_actions SET claimed=? WHERE id=?',((datetime.now(timezone.utc)-timedelta(hours=7)).isoformat(),aid))
  self.assertIsNone(self.claim().json()['action']);self.assertEqual(self.client.post('/api/defender/actions/'+aid+'/recheck',auth=self.auth,headers=self.headers).status_code,200);self.assertEqual(self.claim().json()['action']['kind'],'verify_action')
if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Actions);r=unittest.TextTestRunner(verbosity=2).run(suite)
 import gc;gc.collect();sys.exit(not r.wasSuccessful())
