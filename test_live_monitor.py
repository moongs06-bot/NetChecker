import json,unittest,uuid
from datetime import datetime,timedelta,timezone
from pathlib import Path
import test_netchecker as support
import server,live_monitor

class LiveMonitorTests(unittest.TestCase):
 setUp=support.Tests.setUp
 def anchor(self):return datetime.now(timezone.utc).replace(second=0,microsecond=0)
 def device(self,label,ratio=1,role='pc',baseline=True,stale=False,invalid=False,cpu=20,ram=40):
  ident='qa-'+uuid.uuid4().hex[:8];end=self.anchor();start=end-timedelta(minutes=5)
  with server.db() as c:
   c.execute('INSERT INTO devices VALUES(?,?,?,?,?,?,?)',(ident,label,role,'unused',1,server.now(),'{}'))
   c.execute('INSERT INTO enrollment_requests VALUES(?,?,?,?,?,?,?,?,?,?,?)',(str(uuid.uuid4()),'h'+ident,label,json.dumps(['169.254.1.1','192.0.2.10','fe80::1']),'[]','test','x','approved',ident,server.now(),server.now()))
   for i in range(-359 if baseline else 1,6):
    ts=start+timedelta(minutes=i)-(timedelta(hours=10) if stale else timedelta())
    p={'counter_valid':not invalid,'interval_seconds':60,'tx_bytes':600000*(ratio if i>0 else 1),'rx_bytes':400000*(ratio if i>0 else 1),'resource_collection_ok':True,'cpu_percent':cpu,'memory_percent':ram,'disk_percent':30}
    c.execute('INSERT INTO samples VALUES(?,?,?,?,?)',(ident,str(uuid.uuid4()),ts.isoformat(),ts.isoformat(),json.dumps(p)))
  return ident
 def build(self,cache=None):
  with server.db() as c:return live_monitor.build(c,self.anchor(),cache)
 def test_separation_order_thresholds_and_safe_ips(self):
  self.device('warn',3);self.device('caution',1.5);self.device('normal',1.499);self.device('ERP',10,'erp')
  result=self.build();self.assertEqual([d['label'] for d in result['pcs']],['warn','caution','normal'])
  self.assertEqual([d['severity'] for d in result['pcs']],['warning','caution','none']);self.assertEqual(len(result['servers']),1)
  self.assertAlmostEqual(result['pcs'][0]['total_bps'],50000)
  self.assertEqual(result['pcs'][0]['ips'],['192.0.2.10'])
 def test_stale_missing_baseline_and_invalid_are_not_zero_or_normal(self):
  self.device('stale',10,stale=True);self.device('missing-history',10,baseline=False);self.device('invalid',10,invalid=True)
  result={d['label']:d for d in self.build()['pcs']}
  self.assertEqual(result['stale']['state'],'stale');self.assertIsNone(result['stale']['total_bps']);self.assertFalse(result['stale']['alerts'])
  self.assertEqual(result['missing-history']['comparison'],'비교 대기');self.assertFalse(result['missing-history']['alerts'])
  self.assertIsNone(result['invalid']['total_bps']);self.assertIsNone(result['invalid']['ratio_percent'])
 def test_resource_alert_requires_three_consecutive_observations(self):
  ident=self.device('busy',cpu=96)
  self.assertEqual(self.build()['pcs'][0]['severity'],'warning')
  with server.db() as c:
   c.execute("UPDATE samples SET payload=json_set(payload,'$.cpu_percent',20) WHERE device=? AND ts=?",(ident,(self.anchor()-timedelta(minutes=1)).isoformat()))
  self.assertFalse(self.build()['pcs'][0]['alerts'])
 def test_peak_is_recent_five_minutes(self):
  ident=self.device('ERP peaks',role='erp',cpu=20,ram=40)
  with server.db() as c:
   for minutes,cpu,ram in [(10,99,99),(2,87,91)]:
    c.execute("UPDATE samples SET payload=json_set(payload,'$.cpu_percent',?,'$.memory_percent',?) WHERE device=? AND ts=?",(cpu,ram,ident,(self.anchor()-timedelta(minutes=minutes)).isoformat()))
  d=self.build()['servers'][0]
  self.assertEqual((d['cpu'],d['ram']),(20,40));self.assertEqual((d['cpu_max'],d['ram_max']),(87,91))
 def test_baseline_cache_and_auth(self):
  self.device('cached');cache={};self.build(cache);first=next(iter(cache.values()));self.build(cache);self.assertIs(first,next(iter(cache.values())))
  self.assertEqual(self.client.get('/api/live-monitor').status_code,401)
  r=self.client.get('/api/live-monitor',auth=self.auth);self.assertEqual(r.status_code,200);self.assertEqual(r.headers['cache-control'],'no-store')
  self.assertNotIn('mac',r.text);self.assertEqual(len(r.json()['pcs']),1)
  for path in ('live-monitor.js','live-monitor.css'):
   self.assertEqual(self.client.get('/'+path).status_code,401)
   self.assertEqual(self.client.get('/'+path,auth=self.auth).status_code,200)
 def test_generate_visual_fixture(self):
  self.device('ERP · 업무 서버',1.2,'erp');self.device('AD · 인증 서버',1,'ad');self.device('PLM · 설계 서버',3.3,'plm',ram=96)
  self.device('설계팀-PC-021',3.2);self.device('생산팀-PC-008',1.7);self.device('영업팀-PC-004',1.2)
  self.device('경영지원-PC-017',1,ram=92);self.device('자료부족-PC',baseline=False);self.device('미수집-PC',stale=True)
  for i in range(51):self.device('업무-PC-'+str(i+1).zfill(3),ratio=.9-i*.01,baseline=False)
  value=self.build();out=Path('/opt/netchecker-live-check/qa');out.mkdir(exist_ok=True);(out/'monitor.json').write_text(json.dumps(value,ensure_ascii=False))

if __name__=='__main__':unittest.main()
