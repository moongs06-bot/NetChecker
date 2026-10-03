import json,unittest,uuid
from datetime import datetime,timedelta,timezone
import test_netchecker as support
import server,live_monitor

class RankingTests(unittest.TestCase):
 def setUp(self):support.Tests.setUp(self);live_monitor._rankings.clear()
 def end(self):return datetime(2026,10,1,3,tzinfo=timezone.utc)
 def device(self,name,role='pc'):
  with server.db() as c:c.execute('INSERT INTO devices VALUES(?,?,?,?,?,?,?)',(name,name,role,'unused',1,server.now(),'{}'))
 def sample(self,ident,time,bytes=100,seconds=60,valid=True):
  p={'counter_valid':valid,'interval_seconds':seconds,'tx_bytes':bytes*.6,'rx_bytes':bytes*.4,'resource_collection_ok':True,'cpu_percent':25,'memory_percent':50,'disk_percent':20}
  with server.db() as c:c.execute('INSERT INTO samples VALUES(?,?,?,?,?)',(ident,str(uuid.uuid4()),time.isoformat(),time.isoformat(),json.dumps(p)))
 def build(self,hours):
  with server.db() as c:return live_monitor.build_ranking(c,hours,self.end())
 def test_period_changes_ranking_and_excludes_servers(self):
  for name in ('recent','older'):self.device(name)
  self.device('erp','erp');self.sample('erp',self.end(),9000)
  self.sample('recent',self.end()-timedelta(minutes=20),100)
  self.sample('older',self.end()-timedelta(minutes=90),500)
  self.assertEqual(self.build(1)['pcs'][0]['id'],'recent')
  self.assertEqual(self.build(2)['pcs'][0]['id'],'older')
  for hours in live_monitor.HOURS:
   result=self.build(hours);self.assertEqual(result['hours'],hours);self.assertEqual(len(result['pcs']),2);self.assertEqual(len(result['servers']),1);self.assertEqual(result['servers'][0]['total_bytes'],9000)
   self.assertEqual(datetime.fromisoformat(result['window_end'])-datetime.fromisoformat(result['window_start']),timedelta(hours=hours))
 def test_clip_boundary_missing_not_zero_and_resources(self):
  for ident in ('clipped','zero','missing'):self.device(ident)
  start=self.end()-timedelta(hours=24)
  self.sample('clipped',start+timedelta(seconds=30),1200,120)
  self.sample('clipped',start-timedelta(minutes=1),1000)
  self.sample('clipped',self.end()+timedelta(minutes=1),1000)
  self.sample('zero',self.end(),0);self.sample('missing',self.end(),700,valid=False)
  result=self.build(24)['pcs'];self.assertEqual([r['id'] for r in result],['clipped','zero','missing'])
  self.assertEqual(result[0]['total_bytes'],300);self.assertEqual(result[0]['covered_seconds'],30)
  self.assertEqual(result[1]['total_bytes'],0);self.assertIsNone(result[2]['total_bytes']);self.assertIsNone(result[2]['rank'])
  self.assertEqual(result[0]['cpu_avg'],25);self.assertEqual(result[0]['cpu_max'],25);self.assertEqual(result[0]['ram_max'],50)
 def test_server_trend_clips_and_preserves_missing(self):
  self.device('erp','erp');self.device('empty','ad')
  start=self.end()-timedelta(hours=2)
  self.sample('erp',start+timedelta(seconds=30),1200,120)
  self.sample('erp',self.end(),600,60)
  result=self.build(2);d=next(d for d in result['servers'] if d['id']=='erp')
  self.assertEqual(d['total_bytes'],900)
  self.assertEqual(d['window_start'],result['window_start']);self.assertEqual(d['window_end'],result['window_end'])
  self.assertAlmostEqual(sum((p['mbps'] or 0)*1e6/8*p['covered_seconds'] for p in d['trend']),900)
  self.assertTrue(any(p['mbps'] is None for p in d['trend']))
  empty=next(d for d in result['servers'] if d['id']=='empty')
  self.assertIsNone(empty['total_bytes']);self.assertTrue(all(p['mbps'] is None for p in empty['trend']))
 def test_authorization_and_allowed_periods(self):
  self.assertEqual(self.client.get('/api/traffic-ranking?hours=1').status_code,401)
  for hours in (0,3,48):self.assertEqual(self.client.get('/api/traffic-ranking?hours='+str(hours),auth=self.auth).status_code,422)
  for hours in live_monitor.HOURS:
   r=self.client.get('/api/traffic-ranking?hours='+str(hours),auth=self.auth);self.assertEqual(r.status_code,200);self.assertEqual(r.json()['hours'],hours)

if __name__=='__main__':unittest.main()
