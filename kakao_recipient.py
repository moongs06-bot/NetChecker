"""Recipient consent onboarding, isolated from the sender OAuth credentials."""
import json,secrets,time
from html import escape
from urllib.parse import urlencode
import httpx
from fastapi import Request,HTTPException
from fastapi.responses import HTMLResponse,RedirectResponse
import integrations as i
COOKIE='nc_kakao_recipient_state'

def init(s):
 with s.db() as c:c.executescript("CREATE TABLE IF NOT EXISTS kakao_recipient_invites(token TEXT PRIMARY KEY,expires REAL,binding TEXT); CREATE TABLE IF NOT EXISTS kakao_recipient_states(token TEXT PRIMARY KEY,expires REAL,binding TEXT);")

def binding(s,v):return s.digest(v.get('kakao_key','')+':'+v.get('recipient_binding',''))

def page(title,body,status=200):
 return HTMLResponse('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NetChecker 담당자 등록</title><body style="font-family:sans-serif;background:#eef3fa;color:#172c4c;padding:24px"><main style="max-width:520px;margin:8vh auto;background:white;padding:32px;border-radius:20px"><h1 style="font-size:24px">'+escape(title)+'</h1>'+body+'</main></body></html>',status_code=status)

def valid_invite(s,token):
 v=i.read(s)
 with s.db() as c:row=c.execute('SELECT expires,binding FROM kakao_recipient_invites WHERE token=?',(s.digest(token),)).fetchone()
 if not row or row['expires']<time.time() or not v.get('refresh_token') or row['binding']!=binding(s,v):raise HTTPException(400,'등록 링크가 만료됐거나 발신 계정이 변경됐습니다. 관리자에게 새 링크를 요청해 주세요.')
 return v

async def callback(s,request,code,state):
 cookie=request.cookies.get(COOKIE,'')
 if not cookie or not secrets.compare_digest(cookie,state):return page('등록 요청 확인 실패','<p>등록 링크를 같은 브라우저에서 다시 열어 주세요.</p>',400)
 async with i.lock:
  v=i.read(s)
  with s.db() as c:
   row=c.execute('SELECT expires,binding FROM kakao_recipient_states WHERE token=?',(s.digest(state),)).fetchone()
   c.execute('DELETE FROM kakao_recipient_states WHERE token=?',(s.digest(state),))
  if not row or row['expires']<time.time() or row['binding']!=binding(s,v) or not v.get('refresh_token'):return page('등록 요청 만료','<p>관리자에게 새 등록 링크를 요청해 주세요.</p>',400)
  if not code:return page('등록이 완료되지 않았습니다','<p>동의를 취소하셨습니다. 등록 링크에서 다시 진행할 수 있습니다.</p>',400)
  try:
   async with httpx.AsyncClient(timeout=15) as client:
    response=await client.post('https://kauth.kakao.com/oauth/token',data={'grant_type':'authorization_code','client_id':v['kakao_key'],'client_secret':v.get('kakao_secret',''),'redirect_uri':i.REDIRECT,'code':code})
    response.raise_for_status();access=response.json()['access_token']
    headers={'Authorization':'Bearer '+access}
    me=await client.get('https://kapi.kakao.com/v2/user/me',headers=headers);me.raise_for_status()
    if not me.json().get('id'):raise ValueError('Missing member')
    scopes=await client.get('https://kapi.kakao.com/v2/user/scopes',headers=headers);scopes.raise_for_status()
    agreed={x['id'] for x in scopes.json().get('scopes',[]) if x.get('agreed')}
    if not {'friends','talk_message'}<=agreed:return page('추가 동의가 필요합니다','<p>등록 링크를 다시 열어 친구 목록 제공과 카카오톡 메시지 전송에 동의해 주세요.</p>',400)
  except (httpx.HTTPError,ValueError,KeyError):return page('담당자 등록 실패','<p>잠시 후 등록 링크에서 다시 시도해 주세요. 계속 실패하면 관리자에게 카카오 앱 설정 확인을 요청해 주세요.</p>',400)
  # Recipient tokens are deliberately never saved or used as the sender.
  s.audit('kakao_recipient_consent','completed')
 response=page('담당자 연결·동의 완료','<p>관리자에게 등록 완료를 알려 주세요.</p><p>관리자가 <strong>자동 알림 수신 담당자 선택</strong>을 다시 눌러 담당자를 선택하고 저장하면 등록이 완료됩니다.</p><p>발신자와 카카오톡 친구 관계여야 하며, 해당 앱에서 친구에게 프로필 공개가 허용되어 있어야 목록에 표시됩니다.</p><p>이 절차는 NetChecker 관리자 권한을 부여하지 않습니다. 창을 닫으셔도 됩니다.</p>')
 response.delete_cookie(COOKIE,path='/');return response

def register(s):
 @s.app.post('/api/integrations/kakao/recipient-invite')
 async def invite(request:Request):
  s.admin(request)
  async with i.lock:
   v=i.read(s)
   if not v.get('refresh_token'):raise HTTPException(400,'먼저 카카오 발신 계정을 연결해 주세요.')
   if not v.get('recipient_binding'):v['recipient_binding']=secrets.token_urlsafe(24);i.write(s,v)
   token=secrets.token_urlsafe(32);expires=time.time()+86400
   with s.db() as c:
    c.execute('DELETE FROM kakao_recipient_invites WHERE expires<?',(time.time(),));c.execute('DELETE FROM kakao_recipient_states WHERE expires<?',(time.time(),))
    c.execute('INSERT INTO kakao_recipient_invites VALUES(?,?,?)',(s.digest(token),expires,binding(s,v)))
   return {'url':i.BASE+'api/integrations/kakao/recipient?'+urlencode({'invite':token}),'expires_in_hours':24}
 @s.app.get('/api/integrations/kakao/recipient')
 async def landing(invite:str=''):
  valid_invite(s,invite)
  url=i.BASE+'api/integrations/kakao/recipient/start?'+urlencode({'invite':invite})
  return page('카카오 알림 담당자 등록','<p>본인의 카카오 계정으로 로그인하고 친구 목록 제공·메시지 전송에 동의해 주세요.</p><p>발신자와 카카오톡 친구여야 합니다. 등록 후 관리자가 수신 대상으로 선택합니다.</p><a style="display:block;background:#fee500;color:#191919;padding:16px;text-align:center;border-radius:10px;text-decoration:none" href="'+escape(url,quote=True)+'">카카오 로그인·동의</a><p>기존 발신 계정은 변경되지 않습니다.</p>')
 @s.app.get('/api/integrations/kakao/recipient/start')
 async def start(request:Request,invite:str=''):
  s.budget('recipient:'+request.client.host,20,60)
  async with i.lock:
   v=valid_invite(s,invite);state='recipient_'+secrets.token_urlsafe(32)
   with s.db() as c:c.execute('INSERT INTO kakao_recipient_states VALUES(?,?,?)',(s.digest(state),time.time()+600,binding(s,v)))
  response=RedirectResponse('https://kauth.kakao.com/oauth/authorize?'+urlencode({'client_id':v['kakao_key'],'redirect_uri':i.REDIRECT,'response_type':'code','scope':'friends,talk_message','state':state,'prompt':'select_account'}),status_code=302)
  response.set_cookie(COOKIE,state,max_age=600,httponly=True,secure=True,samesite='lax',path='/');return response
