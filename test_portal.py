import json,unittest,uuid,asyncio
from datetime import datetime,timedelta,timezone
from unittest.mock import patch
import test_netchecker as support
import server,verification
from fastapi.testclient import TestClient
from verification_agent import VerificationInvestigation

class PortalTests(support.Tests):
 def setUp(self):
  super().setUp();server.attempts.clear();(server.STATE/'admin_credentials.json').unlink(missing_ok=True)
  with server.db() as c:
   c.execute('DELETE FROM admin_sessions');c.execute('DELETE FROM verifications')
  self.web=TestClient(server.app,base_url='https://testserver')
 def tearDown(self):(server.STATE/'admin_credentials.json').unlink(missing_ok=True)
 def login(self):return self.web.post('/api/login',headers=self.headers,json={'username':'test','password':'password'})
 def test_login_logout_session_and_csrf(self):
  self.assertIn('loginform',self.web.get('/').text)
  self.assertEqual(self.web.post('/api/login',json={'username':'test','password':'password'}).status_code,403)
  r=self.login();self.assertEqual(r.status_code,200);self.assertIn('HttpOnly',r.headers['set-cookie']);self.assertIn('Secure',r.headers['set-cookie'])
  self.assertEqual(self.web.get('/api/status').status_code,200)
  self.assertEqual(self.web.post('/api/logout',headers={**self.headers,'Origin':'https://evil.test'}).status_code,403)
  self.assertEqual(self.web.post('/api/logout',headers=self.headers).status_code,200)
  self.assertEqual(self.web.get('/api/status',auth=self.auth).status_code,401)
 def test_password_revokes_other_sessions(self):
  self.login();other=TestClient(server.app,base_url='https://testserver');other.cookies.update(self.web.cookies)
  r=self.web.post('/api/password',headers=self.headers,json={'current':'bad','password':'new-password-long'});self.assertEqual(r.status_code,400)
  r=self.web.post('/api/password',headers=self.headers,json={'current':'password','password':'new-password-long'});self.assertEqual(r.status_code,200)
  self.assertEqual(other.get('/api/status').status_code,401)
  self.assertEqual(self.login().status_code,401)
  self.assertEqual(self.web.post('/api/login',headers=self.headers,json={'username':'test','password':'new-password-long'}).status_code,200)
 def test_server_period_and_ip(self):
  d=self.client.post('/api/devices',auth=self.auth,headers=self.headers,json={'label':'ERP','role':'erp'}).json()
  self.client.post('/api/ingest',json=self.sample(),headers={'Authorization':'Bearer '+d['token']})
  for hours in (0,1,2,4,6,8,12,24):
   r=self.client.get('/api/server-overview?hours='+str(hours),auth=self.auth);self.assertEqual(r.status_code,200);v=r.json();self.assertEqual(len(v['servers']),1)
   self.assertAlmostEqual((datetime.fromisoformat(v['window_end'])-datetime.fromisoformat(v['window_start'])).total_seconds(),hours*3600 if hours else 300)
  self.assertEqual(self.client.get('/api/server-overview?hours=3',auth=self.auth).status_code,422)
  self.assertEqual(self.client.get('/api/server-overview?ip=192.0.2.99',auth=self.auth).json()['servers'],[])
 def report(self):
  ident=str(uuid.uuid4())
  with server.db() as c:c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',(ident,'2026-10-01','done',server.now(),json.dumps({'kind':'network','summary':'test','findings':[]})))
  return ident
 def test_peer_ip_search_before_top20_cutoff(self):
  import server_analytics
  ident=self.client.post('/api/devices',auth=self.auth,headers=self.headers,json={'label':'ERP','role':'erp'}).json()['id'];end=datetime.now(timezone.utc)
  flows=[{'remote_ip':'10.2.0.'+str(i),'rx_bytes':100-i,'tx_bytes':100-i} for i in range(1,26)]
  payload={'flows':flows,'truncated':False,'lost_events':0}
  with server.db() as c:
   c.execute('INSERT INTO flow_windows VALUES(?,?,?,?)',(ident,'window',end.isoformat(),json.dumps(payload)))
   value=server_analytics.build(c,end.date().isoformat(),end-timedelta(hours=1),end,search='10.2.0.25',rolling=True)
  self.assertEqual(value['servers'][0]['top20'][0]['ip'],'10.2.0.25');self.assertEqual(value['servers'][0]['top20'][0]['rank'],25)
 def test_comparison_uses_equal_windows_and_missing_is_not_improved(self):
  ident=self.enroll()['id'];at=datetime.now(timezone.utc).replace(second=0,microsecond=0)-timedelta(minutes=15)
  with server.db() as c:
   for minute in range(-9,11):
    p=self.sample();p.update(tx_bytes=600000 if minute<=0 else 60000,rx_bytes=0,cpu_percent=80 if minute<=0 else 40)
    ts=(at+timedelta(minutes=minute)).isoformat();c.execute('INSERT INTO samples VALUES(?,?,?,?,?)',(ident,str(uuid.uuid4()),ts,ts,json.dumps(p)))
   value=verification.comparison(c,ident,at,10)
   self.assertTrue(value['checks']['traffic']['improved']);self.assertEqual(value['before']['coverage_percent'],100);self.assertEqual(value['after']['coverage_percent'],100)
   c.execute('DELETE FROM samples WHERE ts>?',((at+timedelta(minutes=5)).isoformat(),))
   value=verification.comparison(c,ident,at,10);self.assertFalse(value['checks']['traffic']['comparable']);self.assertFalse(value['checks']['traffic']['improved'])
 def test_verification_reservation_and_deletion(self):
  d=self.enroll();rid=self.report();body={'report_id':rid,'device_id':d['id'],'action_kind':'파일 전송 중단','note':'local-only','action_at':server.now(),'minutes':10}
  self.assertEqual(self.client.post('/api/verifications',json=body).status_code,401)
  r=self.client.post('/api/verifications',json=body,auth=self.auth,headers=self.headers);self.assertEqual(r.status_code,200);ident=r.json()['id']
  self.assertEqual(self.client.post('/api/verifications',json=body,auth=self.auth,headers=self.headers).status_code,409)
  p=self.client.get('/api/verifications?report_id='+rid,auth=self.auth).json()[0]['payload']
  value=verification.build(server,p);self.assertNotIn('local-only',json.dumps(value));self.assertFalse(value['target']['checks']['traffic']['comparable'])
  self.assertEqual(self.client.delete('/api/reports/'+rid,auth=self.auth,headers=self.headers).status_code,200)
  self.assertEqual(self.client.get('/api/verifications?report_id='+rid,auth=self.auth).json(),[])
 def test_verification_agent_evidence_gates(self):
  data={'action_kind':'파일 전송 중단','context':{},'target':{'checks':{'traffic':{'comparable':False,'improved':False,'worsened':False}}},'fleet':[]}
  run=VerificationInvestigation({},'2026-10-01','verification',analysis=data)
  with self.assertRaises(ValueError):run.tool('compare_target',{})
  run.tool('plan_verification',{'metrics':['traffic'],'reason':'compare'});run.tool('action_context',{});run.tool('compare_target',{})
  result={'verdict':'improved','summary':'test','next_action':'check','evidence_ids':['action','target']}
  with self.assertRaises(ValueError):run.tool('submit_verification',result)
  result['verdict']='insufficient';self.assertTrue(run.tool('submit_verification',result)['accepted'])
 def test_verification_actual_tool_loop_stub_and_feedback(self):
  d=self.enroll();rid=self.report();ident=str(uuid.uuid4());p={'id':ident,'report_id':rid,'device_id':d['id'],'action_kind':'파일 전송 중단','note':'local-only','action_at':server.now(),'minutes':10,'trace':[]}
  with server.db() as c:c.execute('INSERT INTO verifications VALUES(?,?,?,?,?,?)',(ident,rid,'running',server.now(),server.now(),json.dumps(p)))
  async def fake(conf,data,day,state,mode,progress,analysis):
   self.assertEqual(mode,'verification');self.assertNotIn('local-only',json.dumps(analysis));run=VerificationInvestigation(data,day,mode,progress,analysis)
   for name,args in [('plan_verification',{'metrics':['traffic'],'reason':'coverage'}),('action_context',{}),('compare_target',{}),('submit_verification',{'verdict':'insufficient','summary':'자료 부족입니다.','next_action':'수집을 확인해주세요.','evidence_ids':['action','target']})]:run.tool(name,args)
   return run.result
  with patch('agent_runner.investigate',fake):asyncio.run(verification.execute(server,ident))
  r=self.client.post('/api/verifications/'+ident+'/feedback',auth=self.auth,headers=self.headers,json={'value':'still_slow'});self.assertEqual(r.status_code,200)
  rows=self.client.get('/api/verifications?report_id='+rid,auth=self.auth).json();self.assertEqual(rows[0]['status'],'done');self.assertEqual(rows[0]['payload']['feedback']['value'],'still_slow')

if __name__=='__main__':unittest.main()
