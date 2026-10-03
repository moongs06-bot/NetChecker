import json,unittest,uuid
from test_netchecker import Tests,server
import integrations
class ShareTests(unittest.TestCase):
 def setUp(self):
  h=Tests();h.setUp();self.client=h.client;self.auth=h.auth;self.headers=h.headers;self.rid=str(uuid.uuid4())
  integrations.write(server,{'kakao_js_key':'a'*32,'kakao_key':'SECRET_REST','kakao_secret':'SECRET_CLIENT','refresh_token':'SECRET_REFRESH','auto_notify':True,'notify_self':True})
  with server.db() as c:c.execute('insert into reports values(?,?,?,?,?)',(self.rid,'2026-10-02','done',server.now(),json.dumps({'kind':'daily','summary':'PRIVATE 192.0.2.10'})))
 def get(self):return self.client.get('/api/integrations/kakao/share-config',params={'report_id':self.rid},auth=self.auth)
 def test_share_minimal(self):
  r=self.get();self.assertEqual(r.status_code,200);v=r.json();self.assertEqual(v['javascript_key'],'a'*32);self.assertNotIn('SECRET',r.text);self.assertNotIn('PRIVATE',r.text);self.assertNotIn('192.168',r.text);self.assertTrue(v['template']['link']['webUrl'].endswith('?report='+self.rid))
 def test_auth_required(self):self.assertEqual(self.client.get('/api/integrations/kakao/share-config',params={'report_id':self.rid}).status_code,401)
 def test_missing_key(self):
  integrations.write(server,{});self.assertEqual(self.get().status_code,409)
 def test_deleted(self):
  with server.db() as c:c.execute('update reports set status=? where id=?',('deleted',self.rid))
  self.assertEqual(self.get().status_code,404)
 def test_running(self):
  with server.db() as c:c.execute('update reports set status=? where id=?',('running',self.rid))
  self.assertEqual(self.get().status_code,409)
 def test_save_js_preserves_sender(self):
  r=self.client.post('/api/integrations',auth=self.auth,headers=self.headers,json={'kakao_js_key':'b'*32,'auto_notify':True,'notify_self':True});self.assertEqual(r.status_code,200)
  conf=integrations.read(server);self.assertEqual(conf['refresh_token'],'SECRET_REFRESH');self.assertEqual(conf['kakao_js_key'],'b'*32);self.assertTrue(conf['auto_notify'])
 def test_bad_js_key(self):
  r=self.client.post('/api/integrations',auth=self.auth,headers=self.headers,json={'kakao_js_key':'not-a-js-key'});self.assertEqual(r.status_code,422)
if __name__=='__main__':unittest.main()
