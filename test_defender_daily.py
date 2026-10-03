import sys,unittest,json
from pathlib import Path
from datetime import datetime,timedelta,timezone
root=Path(__file__).parent
sys.path[:0]=[str(root.parent/'defender/testdeps'),str(root),'D:/00.ai_project/NetChecker','/opt/netchecker']
from test_netchecker import Tests
import server,defender_daily
class Daily(unittest.TestCase):
 setUp=Tests.setUp
 enroll=Tests.enroll
 def test_calendar_and_independent_evidence(self):
  d=self.enroll();day='2026-10-02';start,end=server.period(day)
  payload={'channels':[{'channel':'Security','status':'policy_unverified'}],'defender':{'realtime':False},'firewall_enabled':True}
  with server.db() as c:
   for ts in (start,start+timedelta(hours=1),end):c.execute('INSERT INTO defender_history VALUES(?,?,?)',(d['id'],ts.isoformat(),json.dumps(payload)))
   c.execute('INSERT INTO defender_events VALUES(?,?,?,?,?,?)',(d['id'],'Security','1',start.isoformat(),4625,'1.1.1.1'))
   c.execute('INSERT INTO defender_events VALUES(?,?,?,?,?,?)',(d['id'],'Security','2',end.isoformat(),4625,'1.1.1.1'))
  result=defender_daily.aggregate(server,day);row=result['devices'][0]
  self.assertEqual(row['samples'],2);self.assertEqual(row['events']['4625'],1);self.assertEqual(row['observed_hours'],2);self.assertFalse(row['realtime']);self.assertEqual(row['partial_samples'],2);self.assertNotIn('connections',row)
 def test_hide_revoked_only_and_preserve_records(self):
  d=self.enroll();url='/api/devices/'+d['id']+'/list'
  self.assertEqual(self.client.delete(url).status_code,401)
  self.assertEqual(self.client.delete(url,auth=self.auth,headers=self.headers).status_code,409)
  self.client.delete('/api/devices/'+d['id'],auth=self.auth,headers=self.headers)
  self.assertEqual(self.client.delete(url,auth=self.auth,headers=self.headers).status_code,200)
  self.assertFalse(any(x['id']==d['id'] for x in self.client.get('/api/status',auth=self.auth).json()['devices']))
  with server.db() as c:self.assertIsNotNone(c.execute('SELECT * FROM devices WHERE id=?',(d['id'],)).fetchone())
 def test_security_survives_operational_ai_failure(self):
  import asyncio,uuid
  from unittest.mock import patch,AsyncMock
  day='2026-10-02';rid=str(uuid.uuid4())
  with server.db() as c:c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',(rid,day,'running',server.now(),'{}'))
  security={'status':'completed','devices':[],'note':'security evidence retained'}
  with patch('server.snapshot',return_value={'x':{'current':{'samples':1}}}),patch('server.server_analytics.build',return_value={}),patch('server.server_analytics.safe',return_value={}),patch('integrations.context',new=AsyncMock(return_value={})),patch('integrations.send',new=AsyncMock()),patch('defender_daily.build',new=AsyncMock(return_value=security)),patch('agent_runner.investigate',new=AsyncMock(side_effect=RuntimeError('mock network failure'))):
   asyncio.run(server.execute_report(rid,day))
  with server.db() as c:r=c.execute('SELECT status,payload FROM reports WHERE id=?',(rid,)).fetchone()
  self.assertEqual(r['status'],'failed');self.assertEqual(json.loads(r['payload'])['defender_daily'],security)
if __name__=='__main__':unittest.main()

