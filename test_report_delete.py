import asyncio,json,unittest
from unittest.mock import patch,AsyncMock
from datetime import timedelta
import test_netchecker as support
import server

class ReportDeletionTests(unittest.TestCase):
 setUp=support.Tests.setUp
 def insert(self,rid='delete-me',status='done',kind='daily',day='2026-09-30'):
  with server.db() as c:c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',(rid,day,status,server.now(),json.dumps({'kind':kind,'summary':'private summary','trace':[{'detail':'private trace'}],'evidence':{'secret':'private'}})))
 def delete(self,rid='delete-me',**kw):return self.client.delete('/api/reports/'+rid,auth=self.auth,headers=self.headers,**kw)
 def test_delete_content_and_downloads_preserve_samples_and_other_reports(self):
  self.insert();self.insert('keep',kind='network')
  with server.db() as c:c.execute('INSERT INTO samples VALUES(?,?,?,?,?)',('pc','batch',server.now(),server.now(),'{}'))
  self.assertEqual(self.delete().status_code,200)
  self.assertEqual([r['id'] for r in self.client.get('/api/status',auth=self.auth).json()['reports']],['keep'])
  for suffix in ('','/pdf','/log'):self.assertEqual(self.client.get('/api/reports/delete-me'+suffix,auth=self.auth).status_code,404)
  with server.db() as c:
   row=c.execute('SELECT * FROM reports WHERE id=?',('delete-me',)).fetchone();self.assertEqual(row['status'],'deleted');self.assertEqual(json.loads(row['payload']),{'kind':'daily'})
   self.assertEqual(c.execute('SELECT COUNT(*) FROM samples').fetchone()[0],1)
   self.assertEqual(c.execute("SELECT COUNT(*) FROM audit WHERE action='report_deleted'").fetchone()[0],1)
  self.assertEqual(self.delete().status_code,404)
 def test_auth_csrf_running_missing(self):
  self.insert(status='running')
  self.assertEqual(self.client.delete('/api/reports/delete-me').status_code,401)
  self.assertEqual(self.client.delete('/api/reports/delete-me',auth=self.auth).status_code,403)
  self.assertEqual(self.delete().status_code,409);self.assertEqual(self.delete('missing').status_code,404)
  with server.db() as c:self.assertIn('private summary',c.execute('SELECT payload FROM reports').fetchone()[0])
 def test_failed_report_deletable_and_daily_not_automatically_regenerated(self):
  fixed=server.datetime.now(server.KST).replace(hour=9);day=(fixed-timedelta(days=1)).date().isoformat();self.insert(status='failed',day=day)
  self.assertEqual(self.delete().status_code,200)
  class Clock:
   @staticmethod
   def now(tz):return fixed.astimezone(tz)
  with patch.object(server,'datetime',Clock),patch.object(server,'enqueue') as enqueue,patch.object(server.asyncio,'sleep',AsyncMock(side_effect=asyncio.CancelledError)):
   with self.assertRaises(asyncio.CancelledError):asyncio.run(server.schedule())
   enqueue.assert_not_called()
 def test_deleted_reports_still_count_toward_daily_limit(self):
  for i in range(20):self.insert(str(i));self.delete(str(i))
  with self.assertRaises(server.HTTPException) as raised:server.enqueue('2026-09-30')
  self.assertEqual(raised.exception.status_code,429)

if __name__=='__main__':unittest.main()
