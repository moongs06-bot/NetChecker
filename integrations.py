"""Public context and opt-in Kakao notifications. Secrets never leave server settings."""
import asyncio,json,os,secrets,time
from datetime import datetime,timedelta
from urllib.parse import urlencode,unquote
import httpx
from fastapi import HTTPException,Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel,Field,ConfigDict
BASE='https://netchecker.example.com/netchecker/'
REDIRECT=BASE+'api/integrations/kakao/callback'
REGIONS=['창원','함안','의왕','밀양']
lock=asyncio.Lock()
def init(s):
 import kakao_recipient
 kakao_recipient.init(s)
 with s.db() as c:c.executescript("CREATE TABLE IF NOT EXISTS integration_cache(key TEXT PRIMARY KEY,expires REAL,payload TEXT); CREATE TABLE IF NOT EXISTS integration_deliveries(id TEXT PRIMARY KEY,created TEXT,status TEXT,detail TEXT);")
def read(s):
 p=s.STATE/'integrations.json'
 return json.loads(p.read_text()) if p.exists() else {}
def write(s,v):
 p=s.STATE/'integrations.json';tmp=s.STATE/'integrations.tmp'
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 with os.fdopen(fd,'w') as f:json.dump(v,f,ensure_ascii=False)
 os.replace(tmp,p);os.chmod(p,0o600)
def status(s):
 v=read(s)
 with s.db() as c:logs=[dict(r) for r in c.execute('SELECT * FROM integration_deliveries ORDER BY created DESC LIMIT 20')]
 return {'kakao_js_key_set':bool(v.get('kakao_js_key')),'public_key_set':bool(v.get('public_key')),'kakao_key_set':bool(v.get('kakao_key')),'kakao_secret_set':bool(v.get('kakao_secret')),'connected':bool(v.get('refresh_token')),'notify_self':v.get('notify_self',False),'auto_notify':v.get('auto_notify',False),'regions':REGIONS,'recipients':v.get('recipients',[]),'redirect_uri':REDIRECT,'deliveries':logs}
class Settings(BaseModel):
 model_config=ConfigDict(extra='forbid')
 public_key:str=Field(default='',max_length=512)
 kakao_key:str=Field(default='',max_length=128)
 kakao_secret:str=Field(default='',max_length=256)
 kakao_js_key:str=Field(default='',pattern=r'^(?:[a-fA-F0-9]{32})?$')
 auto_notify:bool=False
 notify_self:bool=False
class Recipients(BaseModel):
 uuids:list[str]=Field(max_length=50)
async def public_fetch(client,key,path,params):
 r=await client.get('https://apis.data.go.kr/'+path,params={'serviceKey':unquote(key),'dataType':'JSON','_type':'json','numOfRows':100,**params});r.raise_for_status()
 response=r.json()['response'];code=str(response['header']['resultCode'])
 if code=='03':return [],0
 if code!='00':raise ValueError('public API rejected')
 body=response.get('body') or {};items=body.get('items') or {};items=items.get('item',[]) if isinstance(items,dict) else []
 if isinstance(items,dict):items=[items]
 return items,int(body.get('totalCount',len(items)))
async def context(s,day):
 datetime.strptime(day,'%Y-%m-%d');key=read(s).get('public_key');result={'date':day,'regions':REGIONS,'holiday':{'status':'not_configured'},'weather':{'status':'not_configured'},'note':'공휴일은 회사 휴무 확정이 아닙니다. 기상 발표는 장애 원인이나 해당 시각 유효한 특보임을 확정하지 않습니다. 회사 근무·백업 및 현장 전원·회선 기록과 대조하세요.'}
 if not key:return result
 cachekey='public:'+day
 with s.db() as c:r=c.execute('SELECT payload FROM integration_cache WHERE key=? AND expires>?',(cachekey,time.time())).fetchone()
 if r:return json.loads(r['payload'])
 async with httpx.AsyncClient(timeout=8) as client:
  try:
   rows,total=await public_fetch(client,key,'B090041/openapi/service/SpcdeInfoService/getRestDeInfo',{'solYear':day[:4],'solMonth':day[5:7],'pageNo':1})
   names=[str(r.get('dateName','')) for r in rows if str(r.get('locdate'))==day.replace('-','') and r.get('isHoliday')=='Y']
   result['holiday']={'status':'ok','is_public_holiday':bool(names),'names':names,'source':'한국천문연구원 특일 정보'}
  except Exception:result['holiday']={'status':'unavailable','message':'공휴일 조회 실패: 인증키·활용승인을 확인하세요.'}
  try:
   rows,total=await public_fetch(client,key,'1360000/WthrWrnInfoService/getWthrWrnList',{'fromTmFc':day.replace('-',''),'toTmFc':day.replace('-',''),'pageNo':1})
   matching=[];unknown=0
   for row in rows[:15]:
    detail,_=await public_fetch(client,key,'1360000/WthrWrnInfoService/getWthrWrnMsg',{'stnId':row.get('stnId'),'tmFc':row.get('tmFc'),'tmSeq':row.get('tmSeq'),'pageNo':1})
    text=' '.join(str(v) for x in detail for k,v in x.items() if k.startswith('t'))
    regions=[name for name in REGIONS if name in text]
    if not text:unknown+=1
    if regions:matching.append({'regions':regions,'announced_at':str(row.get('tmFc','')),'title':str(row.get('title',''))[:300],'detail':text[:3000]})
   result['weather']={'status':'ok','announcements':matching,'partial':total>15 or unknown>0,'total_announcements':total,'source':'기상청 기상특보 발표 자료','message':'해당 날짜 발표문에서 사업장 지역명을 확인합니다. 이전 날짜부터 유지된 특보와 효력·해제 여부는 이 목록만으로 판단하지 않습니다.'}
  except Exception:result['weather']={'status':'unavailable','message':'기상특보 조회 실패: 인증키·활용승인 또는 발표자료를 확인하세요.'}
 result['checked_at']=s.now()
 with s.db() as c:c.execute('INSERT OR REPLACE INTO integration_cache VALUES(?,?,?)',(cachekey,time.time()+900,json.dumps(result,ensure_ascii=False)))
 return result
async def token(s):
 v=read(s)
 if v.get('access_token') and v.get('expires',0)>time.time()+60:return v['access_token']
 if not v.get('refresh_token'):raise HTTPException(400,'카카오 계정을 먼저 연결하세요.')
 async with httpx.AsyncClient(timeout=15) as client:
  r=await client.post('https://kauth.kakao.com/oauth/token',data={'grant_type':'refresh_token','client_id':v.get('kakao_key',''),'client_secret':v.get('kakao_secret',''),'refresh_token':v['refresh_token']})
  if r.status_code!=200:raise HTTPException(400,'카카오 재연결이 필요합니다.')
  t=r.json();v.update(access_token=t['access_token'],expires=time.time()+t['expires_in']);v['refresh_token']=t.get('refresh_token',v['refresh_token']);write(s,v);return v['access_token']
async def friends(s):
 access=await token(s);found=[]
 async with httpx.AsyncClient(timeout=15) as client:
  for offset in range(0,1000,100):
   r=await client.get('https://kapi.kakao.com/v1/api/talk/friends',headers={'Authorization':'Bearer '+access},params={'offset':offset,'limit':100})
   if r.status_code!=200:raise HTTPException(400,'친구 목록 권한·동의·앱 팀원 설정을 확인하세요.')
   data=r.json();found.extend({'uuid':x['uuid'],'name':x.get('profile_nickname','담당자')} for x in data.get('elements',[]) if x.get('allowed_msg',False))
   if not data.get('after_url'):break
 return found
async def send(s,rid,day,state):
 async with lock:
  v=read(s)
  if not v.get('auto_notify') or not (v.get('recipients') or v.get('notify_self')):return
  with s.db() as c:
   if c.execute('SELECT 1 FROM integration_deliveries WHERE id=?',(rid,)).fetchone():return
   c.execute('INSERT INTO integration_deliveries VALUES(?,?,?,?)',(rid,s.now(),'sending','보고서 알림 발송 중'))
  try:
   access=await token(s);success=0;failed=0
   template={'object_type':'text','text':'NetChecker '+day+' 분석 '+('완료' if state=='done' else '실패')+'. 로그인 후 분석 이력에서 확인하세요.','link':{'web_url':BASE,'mobile_web_url':BASE},'button_title':'보고서 확인'}
   async with httpx.AsyncClient(timeout=15) as client:
    if v.get('notify_self'):
     r=await client.post('https://kapi.kakao.com/v2/api/talk/memo/default/send',headers={'Authorization':'Bearer '+access},data={'template_object':json.dumps(template,ensure_ascii=False)})
     if r.status_code==200 and r.json().get('result_code')==0:success+=1
     else:failed+=1
    recipients=v.get('recipients',[])
    for i in range(0,len(recipients),5):
     group=[x['uuid'] for x in recipients[i:i+5]]
     r=await client.post('https://kapi.kakao.com/v1/api/talk/friends/message/default/send',headers={'Authorization':'Bearer '+access},data={'receiver_uuids':json.dumps(group),'template_object':json.dumps(template,ensure_ascii=False)})
     if r.status_code==200:success+=len(r.json().get('successful_receiver_uuids',[]));failed+=len(group)-len(r.json().get('successful_receiver_uuids',[]))
     else:failed+=len(group)
   state='sent' if failed==0 else 'partial' if success else 'failed';detail=f'성공 {success}명 / 실패 {failed}명'
  except Exception:state='unknown';detail='발송 결과 미확인. 권한·연결 상태를 확인하세요. 중복 방지를 위해 자동 재전송하지 않습니다.'
  with s.db() as c:c.execute('UPDATE integration_deliveries SET status=?,detail=? WHERE id=?',(state,detail,rid))
def register(s):
 app=s.app
 @app.get('/api/integrations')
 async def get(request:Request):s.admin(request);return status(s)
 @app.post('/api/integrations')
 async def save(body:Settings,request:Request):
  s.admin(request)
  async with lock:
   v=read(s)
   if body.kakao_key and body.kakao_key!=v.get('kakao_key'):
    for k in ['access_token','refresh_token','expires','recipients','oauth_state']:v.pop(k,None)
   for k in ['public_key','kakao_key','kakao_secret','kakao_js_key']:
    if getattr(body,k):v[k]=getattr(body,k).strip()
   v['auto_notify']=body.auto_notify;v['notify_self']=body.notify_self;write(s,v)
   with s.db() as c:c.execute('DELETE FROM integration_cache')
  return status(s)
 @app.get('/api/integrations/kakao/share-config')
 async def share_config(request:Request,report_id:str):
  s.admin(request)
  from uuid import UUID
  try:UUID(report_id)
  except ValueError:raise HTTPException(400,'보고서를 먼저 선택해 주세요.')
  with s.db() as c:row=c.execute('SELECT day,status,payload FROM reports WHERE id=?',(report_id,)).fetchone()
  if not row or row['status']=='deleted':raise HTTPException(404,'삭제되었거나 존재하지 않는 보고서입니다.')
  if row['status']=='running':raise HTTPException(409,'분석이 끝난 뒤 공유해 주세요.')
  key=read(s).get('kakao_js_key','')
  if not key:raise HTTPException(409,'외부 연동 설정에 카카오 JavaScript 키를 저장해 주세요. 카카오 개발자 콘솔의 JavaScript SDK 도메인과 제품 링크 웹 도메인에도 https://netchecker.example.com 을 등록해야 합니다.')
  payload=json.loads(row['payload']);kind='네트워크 지연 분석' if payload.get('kind')=='network' else '일일 분석 보고서'
  state='완료' if row['status']=='done' else '확인 필요'
  link=BASE+'?report='+report_id
  return {'javascript_key':key,'template':{'objectType':'text','text':'NetChecker '+row['day']+' '+kind+' · '+state+'\n로그인 후 보고서를 확인해 주세요.','link':{'webUrl':link,'mobileWebUrl':link},'buttonTitle':'보고서 확인'}}
 @app.get('/api/integrations/context')
 async def preview(request:Request,day:str):
  s.admin(request);s.budget('public-preview',5,60)
  try:datetime.strptime(day,'%Y-%m-%d')
  except ValueError:raise HTTPException(400,'날짜 형식 오류')
  return await context(s,day)
 @app.post('/api/integrations/kakao/connect')
 async def connect(request:Request):
  s.admin(request)
  async with lock:
   v=read(s)
   if not v.get('kakao_key'):raise HTTPException(400,'카카오 REST API 키를 먼저 저장하세요.')
   state=secrets.token_urlsafe(32);v['oauth_state']={'hash':s.digest(state),'until':time.time()+600,'session':s.digest(request.cookies.get('nc_session',''))};write(s,v)
  return {'url':'https://kauth.kakao.com/oauth/authorize?'+urlencode({'client_id':v['kakao_key'],'redirect_uri':REDIRECT,'response_type':'code','scope':'talk_message,friends','state':state})}
 @app.get('/api/integrations/kakao/callback')
 async def callback(request:Request,code:str='',state:str=''):
  if state.startswith('recipient_'):
   import kakao_recipient
   return await kakao_recipient.callback(s,request,code,state)
  s.admin(request)
  async with lock:
   v=read(s);pending=v.pop('oauth_state',{});write(s,v)
   if not state or pending.get('hash')!=s.digest(state) or pending.get('until',0)<time.time() or pending.get('session')!=s.digest(request.cookies.get('nc_session','')):raise HTTPException(400,'연결 요청이 만료됐습니다. 다시 연결하세요.')
   async with httpx.AsyncClient(timeout=15) as client:
    r=await client.post('https://kauth.kakao.com/oauth/token',data={'grant_type':'authorization_code','client_id':v['kakao_key'],'client_secret':v.get('kakao_secret',''),'redirect_uri':REDIRECT,'code':code})
   if r.status_code!=200:raise HTTPException(400,'카카오 연결 실패. Redirect URI·동의항목·키를 확인하세요.')
   t=r.json();v.update(access_token=t['access_token'],refresh_token=t['refresh_token'],expires=time.time()+t['expires_in']);v['recipients']=[];v['auto_notify']=False;v['recipient_binding']=secrets.token_urlsafe(24);write(s,v)
  return HTMLResponse('<meta charset="utf-8"><p>카카오 연결 완료. 외부 연동 설정에서 수신 담당자를 선택하고 자동 알림을 켜주세요.</p><a href="'+BASE+'">대시보드로 돌아가기</a>')
 @app.get('/api/integrations/kakao/friends')
 async def getfriends(request:Request):
  s.admin(request)
  async with lock:return await friends(s)
 @app.post('/api/integrations/kakao/recipients')
 async def recipients(body:Recipients,request:Request):
  s.admin(request)
  async with lock:
   available={x['uuid']:x for x in await friends(s)}
   if any(x not in available for x in body.uuids):raise HTTPException(400,'수신 가능 목록에 없는 담당자입니다.')
   v=read(s);v['recipients']=[available[x] for x in dict.fromkeys(body.uuids)];write(s,v)
  return status(s)
 @app.post('/api/integrations/kakao/disconnect')
 async def disconnect(request:Request):
  s.admin(request)
  async with lock:
   v=read(s)
   for k in ['access_token','refresh_token','expires','oauth_state','recipients']:v.pop(k,None)
   v['auto_notify']=False;write(s,v)
  return status(s)

 import kakao_recipient
 kakao_recipient.register(s)
