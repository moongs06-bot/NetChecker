import json,time,unittest
from urllib.parse import urlparse,parse_qs
from unittest.mock import patch
from test_netchecker import Tests,server
import integrations as i
class Response:
 def __init__(self,data):self.data=data
 def raise_for_status(self):pass
 def json(self):return self.data
class MockClient:
 async def __aenter__(self):return self
 async def __aexit__(self,*args):pass
 async def post(self,*args,**kw):return Response({'access_token':'RECIPIENT_ACCESS','refresh_token':'RECIPIENT_REFRESH'})
 async def get(self,url,**kw):return Response({'id':123} if url.endswith('/me') else {'scopes':[{'id':'friends','agreed':True},{'id':'talk_message','agreed':True}]})
class RecipientTests(unittest.TestCase):
 def setUp(self):
  h=Tests();h.setUp();self.client=h.client;self.auth=h.auth;self.headers=h.headers
  i.write(server,{'kakao_key':'a'*32,'kakao_secret':'secret','access_token':'SENDER_ACCESS','refresh_token':'SENDER_REFRESH','auto_notify':True,'recipients':[{'uuid':'original'}]})
 def link(self):
  r=self.client.post('/api/integrations/kakao/recipient-invite',auth=self.auth,headers=self.headers);self.assertEqual(r.status_code,200);return parse_qs(urlparse(r.json()['url']).query)['invite'][0]
 def start(self):
  token=self.link();r=self.client.get('/api/integrations/kakao/recipient/start',params={'invite':token},follow_redirects=False);self.assertEqual(r.status_code,302);return parse_qs(urlparse(r.headers['location']).query)['state'][0]
 def test_requires_admin(self):self.assertEqual(self.client.post('/api/integrations/kakao/recipient-invite',headers=self.headers).status_code,401)
 def test_landing_public_and_no_secrets(self):
  token=self.link();r=self.client.get('/api/integrations/kakao/recipient',params={'invite':token});self.assertEqual(r.status_code,200);self.assertNotIn('SENDER',r.text)
 def test_expired_link(self):
  token=self.link()
  with server.db() as c:c.execute('update kakao_recipient_invites set expires=0')
  self.assertEqual(self.client.get('/api/integrations/kakao/recipient',params={'invite':token}).status_code,400)
 def test_state_binding(self):
  state=self.start();r=self.client.get('/api/integrations/kakao/callback',params={'state':state,'code':'code'},headers={'Cookie':'nc_kakao_recipient_state=wrong'});self.assertEqual(r.status_code,400)
 def test_completion_preserves_sender_and_blocks_replay(self):
  state=self.start();before=i.read(server)
  with patch('kakao_recipient.httpx.AsyncClient',return_value=MockClient()):
   r=self.client.get('/api/integrations/kakao/callback',params={'state':state,'code':'code'},headers={'Cookie':'nc_kakao_recipient_state='+state});self.assertEqual(r.status_code,200);self.assertIn('연결·동의 완료',r.text)
   r=self.client.get('/api/integrations/kakao/callback',params={'state':state,'code':'code'},headers={'Cookie':'nc_kakao_recipient_state='+state});self.assertEqual(r.status_code,400)
  self.assertEqual(i.read(server),before);self.assertNotIn('RECIPIENT_ACCESS',json.dumps(i.read(server)))
 def test_changed_sender_invalidates_invite(self):
  token=self.link();v=i.read(server);v['recipient_binding']='changed';i.write(server,v)
  self.assertEqual(self.client.get('/api/integrations/kakao/recipient',params={'invite':token}).status_code,400)
 def test_denied_consent(self):
  state=self.start();r=self.client.get('/api/integrations/kakao/callback',params={'state':state,'error':'access_denied'},headers={'Cookie':'nc_kakao_recipient_state='+state});self.assertEqual(r.status_code,400);self.assertIn('취소',r.text)
if __name__=='__main__':unittest.main()
