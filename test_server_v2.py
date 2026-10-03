import unittest,json,uuid,copy
from pathlib import Path
from datetime import datetime,timezone,timedelta
from test_netchecker import Tests
import server,server_analytics
from agent_runner import Investigation

class V2(unittest.TestCase):
 setUp=Tests.setUp
 sample=Tests.sample
 registration=Tests.registration
 def approved(self,role,addr):
  body=self.registration();body['ips']=[addr];body['hostname']='QA-'+role
  self.client.post('/api/enrollment/request',json=body)
  r=self.client.post('/api/enrollment/'+body['installation_id']+'/approve',json={'label':'QA-'+role,'role':role},auth=self.auth,headers=self.headers)
  self.assertEqual(r.status_code,200);return r.json()['id'],body['token']
 def fixture(self):
  sid,st=self.approved('erp','10.1.2.3');pid,pt=self.approved('pc','10.1.2.4');now=datetime.now(timezone.utc)-timedelta(seconds=2)
  flow={'window_id':str(uuid.uuid4()),'started_at':(now-timedelta(seconds=60)).isoformat(),'ended_at':now.isoformat(),'lost_events':0,'truncated':False,'flows':[{'local_ip':'10.1.2.3','remote_ip':'10.1.2.4','local_port':443,'remote_port':55000,'protocol':'TCP','tx_bytes':100,'rx_bytes':200}]}
  event={'record_id':'101','time':now.isoformat(),'source_ip':'10.1.2.4','destination_ip':'10.1.2.3','source_port':55000,'destination_port':443,'protocol':'TCP','action':'allowed'}
  events=[event,{**event,'record_id':'102','destination_port':4444},{**event,'record_id':'103','action':'blocked'},{**event,'record_id':'104','source_ip':'10.1.2.3','destination_ip':'10.1.2.4','destination_port':55000}]
  for _ in range(2):
   s={**self.sample(),'flow_window':flow,'flow_status':'running','port_events':events,'port_status':'truncated'}
   r=self.client.post('/api/ingest',json=s,headers={'Authorization':'Bearer '+st});self.assertEqual(r.status_code,200,r.text)
  clientflow={**flow,'window_id':str(uuid.uuid4()),'flows':[{**flow['flows'][0],'local_ip':'10.1.2.4','remote_ip':'10.1.2.3','tx_bytes':9999,'rx_bytes':9999}]}
  self.client.post('/api/ingest',json={**self.sample(),'flow_window':clientflow},headers={'Authorization':'Bearer '+pt})
  return sid,pid
 def overview(self):
  r=self.client.get('/api/server-overview',auth=self.auth);self.assertEqual(r.status_code,200,r.text);return r.json()
 def test_direction_dedup_policy_and_privacy(self):
  sid,pid=self.fixture();v=self.overview();s=v['servers'][0]
  self.assertEqual(s['flow_windows'],1);self.assertEqual(s['top20'][0]['total_bytes'],300);self.assertEqual(s['top20'][0]['to_server_bytes'],200);self.assertEqual(s['top20'][0]['device'],pid)
  self.assertEqual(len(s['port_events']),3);self.assertTrue(s['port_partial']);self.assertEqual(sum(e['count'] for e in s['port_events']),3)
  r=self.client.put('/api/devices/'+sid+'/policy',json={'configured':True,'tcp':[443],'udp':[]},auth=self.auth,headers=self.headers);self.assertEqual(r.status_code,200)
  s=self.overview()['servers'][0];self.assertEqual(len(s['port_events']),2);self.assertEqual({e['port'] for e in s['port_events']},{443,4444});self.assertNotIn(55000,{e['port'] for e in s['port_events']})
  safe=json.dumps(server_analytics.safe(v,server.alias));self.assertNotIn('10.1.2.',safe);self.assertNotIn('QA-erp',safe)
 def test_missing_partial_and_api_access(self):
  sid,st=self.approved('ad','10.1.2.3');v=self.overview()['servers'][0]
  self.assertIsNone(v['total_bytes']);self.assertEqual(v['flow_status'],'not_collected');self.assertIsNone(v['daily'][-1]['tx_bytes'])
  self.assertEqual(self.client.get('/api/server-overview').status_code,401)
  self.assertEqual(self.client.put('/api/devices/'+sid+'/policy',json={'configured':True,'tcp':[70000],'udp':[]},auth=self.auth,headers=self.headers).status_code,422)
  self.assertEqual(self.client.put('/api/devices/'+sid+'/identity',json={'label':'ERP 변경','role':'erp'},auth=self.auth,headers=self.headers).status_code,200)
  self.assertEqual(self.overview()['servers'][0]['label'],'ERP 변경')
 def test_agent_requires_servers_not_every_pc(self):
  data={x:{'device':x,'current':{},'expected':{}} for x in ('srv','pc1','pc2')}
  run=Investigation(data,'2026-09-30','daily',analysis={'servers':[{'id':'srv'}],'pcs':[{'id':'pc1'},{'id':'pc2'}]})
  run.tool('plan_investigation',{'plan':'서버 조사'});run.tool('fleet_overview',{});run.tool('fleet_rankings',{})
  report={'summary':'s','findings':[],'limitations':[]}
  with self.assertRaises(ValueError):run.tool('submit_report',report)
  run.tool('inspect_server',{'device':'srv','reason':'server evidence'})
  self.assertTrue(run.tool('submit_report',report)['accepted']);self.assertEqual(run.seen,{'srv'})
 def test_150_pc_pdf(self):
  self.fixture();v=self.overview();template=v['pcs'][0];v['pcs']=[]
  for i in range(150):
   d=copy.deepcopy(template);d.update(id='qa-pc-'+str(i),label='검증용 PC '+str(i+1),ips=['10.20.0.'+str(i+1)],rank=i+1);v['pcs'].append(d)
  v['counts'].update(registered=151,pcs=150,collected=151)
  for i,d in enumerate(v['servers'][0]['daily']):d.update(tx_bytes=(i+1)*10**9,rx_bytes=(i+2)*10**9,total_bytes=(2*i+3)*10**9)
  report={'id':'synthetic-v2-layout-validation','day':v['day'],'status':'done','created':server.now(),'payload':{'server_report':v,'summary':'가상 자료로 구성한 보고서 레이아웃 검증입니다. 실제 회사 관측 결과가 아닙니다.','findings':[{'device':v['pcs'][0]['id'],'priority':'medium','observation':'가상 CPU 최대값 증가 사례','explanation':'레이아웃 검증을 위한 예시','next_action':'실제 운영 결과로 사용하지 않습니다.','evidence_ids':['observation:'+v['pcs'][0]['id']]}],'limitations':['모든 수치는 합성 검증 자료입니다.'],'trace':[{'time':server.now(),'action':'검증용 실행 기록','tool':'inspect_server','detail':'합성 자료의 표·그래프 출력 확인'}]}}
  from pdf_report import build_report
  content=build_report(report);self.assertTrue(content.startswith(b'%PDF-'))
  out=Path('/opt/netchecker-check/qa');out.mkdir(exist_ok=True);(out/'server-report-150pc.pdf').write_bytes(content);(out/'report.json').write_text(json.dumps(report,ensure_ascii=False))

if __name__=='__main__':unittest.main()
