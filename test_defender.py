import sys,unittest,uuid,json,os
from pathlib import Path
from datetime import datetime,timezone,timedelta
root=Path(__file__).resolve().parent
sys.path[:0]=[str(root.parent/'defender/testdeps'),str(root),os.getenv('NETCHECKER_TEST_SOURCE','D:/00.ai_project/NetChecker')]
from test_netchecker import Tests
import server
class DefenderTests(Tests):
 def setUp(self):
  super().setUp();server.attempts.clear()
  with server.db() as c:
   for t in ('defender_snapshots','defender_events','defender_reviews','defender_actions','defender_inventory'): c.execute('DELETE FROM '+t)
 def body(self):
  now=datetime.now(timezone.utc).isoformat()
  return {'batch_id':str(uuid.uuid4()),'observed_at':now,'version':'0.1.0','channels':[{'channel':'Security','status':'ok'},{'channel':'Microsoft-Windows-Windows Defender/Operational','status':'ok'}],'defender':{'realtime':True,'antivirus':True,'signature_at':now},'events':[{'channel':'Security','record_id':str(i),'event_id':4625,'observed_at':now,'source_ip':'10.1.2.3'} for i in range(10)]}
 def test_defender_lifespan_cleanup_does_not_lock(self):
  from fastapi.testclient import TestClient
  day=(datetime.now(server.KST)-timedelta(days=1)).date().isoformat()
  with server.db() as c:
   c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',(str(uuid.uuid4()),day,'done',server.now(),json.dumps({'kind':'daily'})))
   c.execute('INSERT INTO defender_events VALUES(?,?,?,?,?,?)',('old','Security','99',(datetime.now(timezone.utc)-timedelta(days=35)).isoformat(),4625,None))
  with TestClient(server.app) as client:
   response=client.post('/api/devices',json={'label':'lifecycle-test','role':'pc'},auth=self.auth,headers=self.headers)
   self.assertEqual(response.status_code,200,response.text)
   with server.db() as c:self.assertEqual(c.execute('SELECT count(*) FROM defender_events').fetchone()[0],0)
 def test_defender_auth_dedup_alert_and_revoke(self):
  d=self.enroll();b=self.body();h={'Authorization':'Bearer '+d['token']}
  self.assertEqual(self.client.post('/api/defender/ingest',json=b).status_code,401)
  for _ in range(2): self.assertEqual(self.client.post('/api/defender/ingest',json=b,headers=h).status_code,200)
  with server.db() as c:self.assertEqual(c.execute('SELECT count(*) FROM defender_events').fetchone()[0],10)
  self.assertEqual(self.client.get('/api/defender/status').status_code,401)
  r=self.client.get('/api/defender/status',auth=self.auth).json()['devices'][0]
  self.assertEqual(r['state'],'collecting');self.assertEqual(len(r['alerts']),1)
  self.assertEqual(self.client.post('/api/defender/'+d['id']+'/analyze',auth=self.auth,headers=self.headers).status_code,409)
  self.client.delete('/api/devices/'+d['id'],auth=self.auth,headers=self.headers)
  self.assertEqual(self.client.post('/api/defender/ingest',json=b,headers=h).status_code,401)
 def test_defender_missing_partial_stale_and_monotonic(self):
  d=self.enroll();h={'Authorization':'Bearer '+d['token']}
  self.assertEqual(self.client.get('/api/defender/status',auth=self.auth).json()['devices'][0]['state'],'not_installed')
  b=self.body();b['events']=[];b['channels'][0]['status']='unavailable';b['defender']=None
  self.assertEqual(self.client.post('/api/defender/ingest',json=b,headers=h).status_code,200)
  self.assertEqual(self.client.get('/api/defender/status',auth=self.auth).json()['devices'][0]['state'],'partial')
  older={**b,'observed_at':(datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat()}
  self.client.post('/api/defender/ingest',json=older,headers=h)
  self.assertEqual(self.client.get('/api/defender/status',auth=self.auth).json()['devices'][0]['state'],'partial')
  with server.db() as c:c.execute('UPDATE defender_snapshots SET ts=?',(older['observed_at'],))
  self.assertEqual(self.client.get('/api/defender/status',auth=self.auth).json()['devices'][0]['state'],'stale')
 def test_defender_validation_and_download(self):
  d=self.enroll();h={'Authorization':'Bearer '+d['token']}
  for mutate in (lambda b:b.update(extra='x'),lambda b:b['events'][0].update(source_ip='x'),lambda b:b['events'][0].update(channel='Microsoft-Windows-Windows Defender/Operational'),lambda b:b.update(observed_at='2020-01-01T00:00:00Z')):
   b=self.body();mutate(b);self.assertEqual(self.client.post('/api/defender/ingest',json=b,headers=h).status_code,422)
  self.assertEqual(self.client.get('/downloads/NetChecker-Defender-Setup.exe').status_code,401)
  response=self.client.get('/downloads/NetChecker-Defender-Setup.exe',auth=self.auth)
  self.assertEqual(response.status_code,200);self.assertTrue(response.content.startswith(b'MZ'))
  self.assertEqual(self.client.get('/downloads/security_defender.py',auth=self.auth).status_code,404)
if __name__=='__main__':
 suite=unittest.TestSuite(DefenderTests(name) for name in ('test_defender_lifespan_cleanup_does_not_lock','test_defender_auth_dedup_alert_and_revoke','test_defender_missing_partial_stale_and_monotonic','test_defender_validation_and_download','test_approval_lifecycle','test_ingest_idempotent_deidentified','test_missing_and_invalid'))
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 import gc;gc.collect()
 sys.exit(not result.wasSuccessful())
