import os,tempfile,json,hashlib,unittest,uuid
from pathlib import Path
from datetime import datetime,timezone
TEMP=tempfile.TemporaryDirectory();os.environ['NETCHECKER_STATE']=TEMP.name;os.environ['NETCHECKER_CONFIG']=TEMP.name+'/config.json'
Path(os.environ['NETCHECKER_CONFIG']).write_text(json.dumps({'admin_user':'test','admin_salt':'00'*16,'admin_hash':hashlib.pbkdf2_hmac('sha256',b'password',bytes(16),200000).hex(),'alias_secret':'test-secret'}))
from fastapi.testclient import TestClient
import server
from agent_runner import Investigation

class Tests(unittest.TestCase):
 def setUp(self):
  server.init();self.client=TestClient(server.app);self.auth=('test','password');self.headers={'X-NetChecker':'1'}
  with server.db() as c:
   for table in ('devices','samples','reports','enrollment_requests','flow_windows','port_events','server_policies','audit','verifications','admin_sessions'):c.execute('DELETE FROM '+table)
 def enroll(self):return self.client.post('/api/devices',json={'label':'test-pc','role':'pc'},auth=self.auth,headers=self.headers).json()
 def sample(self):return {'batch_id':str(uuid.uuid4()),'observed_at':datetime.now(timezone.utc).isoformat(),'interval_seconds':60,'tx_bytes':100,'rx_bytes':200,'counter_valid':True,'cpu_percent':10,'memory_percent':20,'disk_percent':30,'connections':[{'remote_ip':'192.0.2.10','remote_port':445,'process':'private-process','state':'Established'}],'connections_total':1,'connection_collection_ok':True,'resource_collection_ok':True,'collector_version':'test'}
 def test_auth_and_unlimited_registration(self):
  self.assertEqual(self.client.get('/api/status').status_code,401)
  self.assertEqual(self.client.post('/api/devices',json={'label':'x','role':'pc'},auth=self.auth).status_code,403)
  for _ in range(15):self.enroll()
  self.assertEqual(self.client.post('/api/devices',json={'label':'x','role':'pc'},auth=self.auth,headers=self.headers).status_code,200)
 def test_approval_over_ten_devices(self):
  for _ in range(15):self.enroll()
  body=self.registration();self.client.post('/api/enrollment/request',json=body)
  r=self.client.post('/api/enrollment/'+body['installation_id']+'/approve',json={'label':'extra-server','role':'erp'},auth=self.auth,headers=self.headers)
  self.assertEqual(r.status_code,200)
  self.assertEqual(len(self.client.get('/api/status',auth=self.auth).json()['devices']),16)
 def test_ingest_idempotent_deidentified(self):
  d=self.enroll();s=self.sample()
  self.assertEqual(self.client.post('/api/ingest',json=s).status_code,401)
  for _ in range(2):self.assertEqual(self.client.post('/api/ingest',json=s,headers={'Authorization':'Bearer '+d['token']}).status_code,200)
  data=server.snapshot(datetime.now(server.KST).date().isoformat(),30)
  self.assertEqual(data[d['id']]['current']['samples'],1)
  self.assertNotIn('192.0.2.10',json.dumps(data));self.assertNotIn('private-process',json.dumps(data));self.assertNotIn('test-pc',json.dumps(data))
  self.client.delete('/api/devices/'+d['id'],auth=self.auth,headers=self.headers)
  self.assertEqual(self.client.post('/api/ingest',json=s,headers={'Authorization':'Bearer '+d['token']}).status_code,401)
 def test_missing_and_invalid(self):
  d=self.enroll();data=server.snapshot(datetime.now(server.KST).date().isoformat(),5)
  self.assertEqual(data[d['id']]['current']['samples'],0);self.assertIsNone(data[d['id']]['current']['max_cpu'])
  s=self.sample();s['connections'][0]['remote_ip']='not-ip'
  self.assertEqual(self.client.post('/api/ingest',json=s,headers={'Authorization':'Bearer '+d['token']}).status_code,422)
 def test_evidence_gate(self):
  run=Investigation({'pc-x':{'device':'pc-x','current':{},'expected':{}}},'2026-09-30','network')
  with self.assertRaises(ValueError):run.tool('fleet_overview',{})
  run.tool('plan_investigation',{'plan':'compare'});run.tool('fleet_overview',{})
  report={'summary':'s','findings':[],'limitations':[]}
  with self.assertRaises(ValueError):run.tool('submit_report',report)
  run.tool('fleet_rankings',{});run.tool('inspect_device',{'device':'pc-x','reason':'compare'})
  run.tool('check_expected_activity',{'device':'pc-x'})
  bad={**report,'findings':[{'device':'pc-x','priority':'high','evidence_ids':['invented']}]}
  with self.assertRaises(ValueError):run.tool('submit_report',bad)
  self.assertTrue(run.tool('submit_report',report)['accepted'])
 def registration(self):return {'installation_id':str(uuid.uuid4()),'token':uuid.uuid4().hex+uuid.uuid4().hex,'hostname':'TEST-SERVER','ips':['10.1.2.3'],'macs':['00-11-22-33-44-55'],'os_name':'Windows test'}
 def test_approval_lifecycle(self):
  body=self.registration();r=self.client.post('/api/enrollment/request',json=body)
  self.assertEqual(r.status_code,200);self.assertEqual(r.json()['status'],'pending')
  self.assertEqual(self.client.post('/api/ingest',json=self.sample(),headers={'Authorization':'Bearer '+body['token']}).status_code,401)
  bad={**body,'token':'f'*64};self.assertEqual(self.client.post('/api/enrollment/request',json=bad).status_code,403)
  path='/api/enrollment/'+body['installation_id']+'/approve'
  self.assertEqual(self.client.post(path,json={'label':'test','role':'ad'}).status_code,401)
  a=self.client.post(path,json={'label':'test','role':'ad'},auth=self.auth,headers=self.headers)
  self.assertEqual(a.status_code,200);ident=a.json()['id']
  self.assertEqual(self.client.post(path,json={'label':'test','role':'ad'},auth=self.auth,headers=self.headers).json()['id'],ident)
  self.assertEqual(self.client.post('/api/enrollment/request',json=body).json()['status'],'approved')
  self.assertEqual(self.client.post('/api/ingest',json=self.sample(),headers={'Authorization':'Bearer '+body['token']}).status_code,200)
  status=self.client.get('/api/status',auth=self.auth).json();self.assertEqual(len(status['pending']),0);self.assertEqual(status['devices'][0]['role'],'ad');self.assertIn('00:11:22:33:44:55',status['devices'][0]['macs']);self.assertNotIn(body['token'],json.dumps(status))
  body['ips']=['10.1.2.4'];self.client.post('/api/enrollment/request',json=body)
  self.assertIn('10.1.2.4',self.client.get('/api/status',auth=self.auth).json()['devices'][0]['ips'])
  self.client.delete('/api/devices/'+ident,auth=self.auth,headers=self.headers)
  self.assertEqual(self.client.post('/api/enrollment/request',json=body).json()['status'],'rejected')
  self.assertEqual(self.client.post('/api/ingest',json=self.sample(),headers={'Authorization':'Bearer '+body['token']}).status_code,401)
 def test_rejection_and_validation(self):
  body=self.registration();self.client.post('/api/enrollment/request',json=body)
  r=self.client.post('/api/enrollment/'+body['installation_id']+'/reject',auth=self.auth,headers=self.headers)
  self.assertEqual(r.status_code,200)
  self.assertEqual(self.client.post('/api/enrollment/request',json=body).json()['status'],'rejected')
  body['macs']=['invalid'];self.assertEqual(self.client.post('/api/enrollment/request',json=body).status_code,422)
 def test_traffic_valid_only_no_duplicates(self):
  self.assertEqual(self.client.get('/api/traffic').status_code,401)
  d=self.enroll();h={'Authorization':'Bearer '+d['token']};sample=self.sample()
  for _ in range(2):self.client.post('/api/ingest',json=sample,headers=h)
  invalid={**self.sample(),'counter_valid':False,'tx_bytes':10000};self.client.post('/api/ingest',json=invalid,headers=h)
  result=self.client.get('/api/traffic',auth=self.auth).json()
  self.assertEqual(result['totals'],{'tx_bytes':100,'rx_bytes':200,'total_bytes':300})
  self.assertEqual(result['devices'][0]['valid_samples'],1)
  self.assertEqual(result['devices'][0]['covered_seconds'],60)
 def test_pdf_authorization_and_running_gate(self):
  rid=str(uuid.uuid4());day=datetime.now(server.KST).date().isoformat()
  with server.db() as c:c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',(rid,day,'running',server.now(),'{}'))
  path='/api/reports/'+rid+'/pdf'
  self.assertEqual(self.client.get(path).status_code,401)
  self.assertEqual(self.client.get(path,auth=self.auth).status_code,409)
  with server.db() as c:c.execute('UPDATE reports SET status=?,payload=? WHERE id=?',('done',json.dumps({'summary':'수집 자료가 없습니다.','mode':'no_data','trace':[],'findings':[]}),rid))
  response=self.client.get(path,auth=self.auth)
  self.assertEqual(response.status_code,200);self.assertTrue(response.content.startswith(b'%PDF-'));self.assertEqual(response.headers['content-type'],'application/pdf')
if __name__=='__main__':unittest.main()
