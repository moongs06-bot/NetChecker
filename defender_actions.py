"""Approved, typed endpoint actions. AI cannot approve or execute actions."""
import json,uuid,hashlib,secrets,ipaddress
from datetime import datetime,timezone,timedelta
from fastapi import Request,HTTPException
from pydantic import BaseModel,ConfigDict,Field,field_validator
class Strict(BaseModel):model_config=ConfigDict(extra='forbid')
class Update(Strict):
 id:uuid.UUID
 revision:int=Field(ge=1,le=100000)
 title:str=Field(max_length=300)
 kb:list[str]=Field(default_factory=list,max_length=20)
 reboot_may_be_needed:bool=True
class Inventory(Strict):
 observed_at:datetime
 status:str=Field(pattern='^(available|unavailable|scanning)$')
 updates:list[Update]=Field(default_factory=list,max_length=100)
 os_build:str=Field(default='',max_length=100)
 firewall_enabled:bool|None=None
 @field_validator('observed_at')
 @classmethod
 def aware(cls,v):
  if v.tzinfo is None:raise ValueError('Timezone required')
  if not datetime.now(timezone.utc)-timedelta(days=2)<=v<=datetime.now(timezone.utc)+timedelta(minutes=5):raise ValueError('Stale inventory')
  return v
class Proposal(Strict):
 kind:str=Field(pattern='^(update_install|firewall_block|firewall_remove)$')
 target:str=Field(max_length=100)
 reason:str=Field(min_length=5,max_length=500)
class Approval(Strict):
 target_device:str
 backup_confirmed:bool=False
 impact_confirmed:bool
 not_before:datetime
 @field_validator('not_before')
 @classmethod
 def aware(cls,v):
  if v.tzinfo is None:raise ValueError('Timezone required')
  if not datetime.now(timezone.utc)-timedelta(minutes=5)<=v<=datetime.now(timezone.utc)+timedelta(days=7):raise ValueError('Schedule within 7 days')
  return v
class Result(Strict):
 claim:str=Field(min_length=40,max_length=100)
 success:bool
 verified:bool
 reboot_required:bool=False
 detail:str=Field(max_length=800)
class Cancel(Strict):reason:str=Field(min_length=3,max_length=300)
def init(s):
 with s.db() as c:c.executescript('''
 CREATE TABLE IF NOT EXISTS defender_inventory_history(device TEXT,ts TEXT,payload TEXT,PRIMARY KEY(device,ts));
 CREATE TABLE IF NOT EXISTS defender_inventory(device TEXT PRIMARY KEY,ts TEXT,payload TEXT);
 CREATE TABLE IF NOT EXISTS defender_actions(id TEXT PRIMARY KEY,device TEXT,kind TEXT,target TEXT,reason TEXT,status TEXT,created TEXT,approved TEXT,not_before TEXT,expires TEXT,claim_hash TEXT,claimed TEXT,payload TEXT,result TEXT);
 CREATE INDEX IF NOT EXISTS defender_action_device ON defender_actions(device,created);
 ''')
def active(s,ident):
 with s.db() as c:r=c.execute('SELECT * FROM devices WHERE id=? AND active=1',(ident,)).fetchone()
 if not r:raise HTTPException(404,'활성 장비가 없습니다.')
 return dict(r)
def listing(s,ident):
 with s.db() as c:rows=c.execute('SELECT id,kind,target,reason,status,created,approved,not_before,expires,result FROM defender_actions WHERE device=? ORDER BY created DESC LIMIT 20',(ident,)).fetchall()
 return [{**dict(r),'result':json.loads(r['result']) if r['result'] else None} for r in rows]
def view(s,ident):
 with s.db() as c:r=c.execute('SELECT payload FROM defender_inventory WHERE device=?',(ident,)).fetchone()
 return {'inventory':json.loads(r['payload']) if r else None,'actions':listing(s,ident)}
def public_ip(value):
 try:addr=ipaddress.ip_address(value)
 except ValueError:raise HTTPException(422,'정확한 단일 IP를 입력하세요.')
 if addr.version!=4:raise HTTPException(422,'첫 버전은 단일 공인 IPv4만 지원합니다.')
 if not addr.is_global:raise HTTPException(422,'첫 버전은 공인 IP만 차단합니다. 내부망·관리 주소는 차단하지 않습니다.')
 return str(addr)
def install(s):
 @s.app.post('/api/defender/inventory')
 async def inventory(body:Inventory,request:Request):
  d=s.token_device(request);v=body.model_dump(mode='json');ts=body.observed_at.astimezone(timezone.utc).isoformat()
  with s.db() as c:
   c.execute('INSERT OR IGNORE INTO defender_inventory_history VALUES(?,?,?)',(d['id'],ts,json.dumps(v)))
   c.execute('DELETE FROM defender_inventory_history WHERE ts<?',((datetime.now(timezone.utc)-timedelta(days=30)).isoformat(),))
   c.execute('INSERT INTO defender_inventory VALUES(?,?,?) ON CONFLICT(device) DO UPDATE SET ts=excluded.ts,payload=excluded.payload WHERE excluded.ts>defender_inventory.ts',(d['id'],ts,json.dumps(v)))
  return {'ok':True}
 @s.app.get('/api/defender/{ident}/actions')
 async def actions(ident:str,request:Request):s.admin(request);active(s,ident);return view(s,ident)
 @s.app.post('/api/defender/{ident}/actions')
 async def propose(ident:str,body:Proposal,request:Request):
  s.admin(request);active(s,ident);payload={};target=body.target;now=datetime.now(timezone.utc)
  if body.kind=='update_install':
   data=view(s,ident)['inventory']
   if not data or data['status']!='available' or now-datetime.fromisoformat(data['observed_at'])>timedelta(hours=2):raise HTTPException(409,'2시간 이내 Windows Update 조회 자료가 필요합니다.')
   update=next((u for u in data['updates'] if u['id']==target),None)
   if not update:raise HTTPException(409,'장비가 보고한 업데이트만 제안할 수 있습니다.')
   payload={'update_id':update['id'],'revision':update['revision'],'title':update['title']}
  elif body.kind=='firewall_block':
   target=public_ip(target)
   if target==request.client.host:raise HTTPException(409,'현재 관리자 접속 IP는 차단할 수 없습니다.')
   cutoff=(now-timedelta(hours=24)).isoformat()
   with s.db() as c:found=c.execute('SELECT 1 FROM defender_events WHERE device=? AND ip=? AND event=4625 AND ts>=?',(ident,target,cutoff)).fetchone()
   if not found:raise HTTPException(409,'최근 24시간 해당 IP의 로그인 실패 근거가 필요합니다.')
   payload={'remote_ip':target,'duration_minutes':60}
  else:
   try:target=str(uuid.UUID(target))
   except ValueError:raise HTTPException(422,'차단 조치 ID가 필요합니다.')
   with s.db() as c:r=c.execute("SELECT * FROM defender_actions WHERE id=? AND device=? AND kind='firewall_block' AND status IN ('verified','verification_needed')",(target,ident)).fetchone()
   if not r:raise HTTPException(409,'이 장비에 실행한 넷체커 차단 조치만 해제할 수 있습니다.')
   payload={'rule_id':target}
  aid=str(uuid.uuid4())
  with s.db() as c:
   if c.execute("SELECT 1 FROM defender_actions WHERE device=? AND kind=? AND target=? AND status IN ('proposed','approved','claimed')",(ident,body.kind,target)).fetchone():raise HTTPException(409,'동일한 조치가 이미 대기 중입니다.')
   c.execute('INSERT INTO defender_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(aid,ident,body.kind,target,body.reason,'proposed',s.now(),None,None,None,None,None,json.dumps(payload),None))
  s.audit('defender_proposed',aid);return {'id':aid,'status':'proposed'}
 @s.app.post('/api/defender/actions/{aid}/approve')
 async def approve(aid:str,body:Approval,request:Request):
  s.admin(request);now=datetime.now(timezone.utc)
  with s.db() as c:
   c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT * FROM defender_actions WHERE id=?',(aid,)).fetchone()
   if not r or r['status']!='proposed':raise HTTPException(409,'승인 대기 조치만 승인할 수 있습니다.')
   active(s,r['device'])
   if body.target_device!=r['device'] or not body.impact_confirmed or (r['kind']=='update_install' and not body.backup_confirmed):raise HTTPException(422,'대상 장비·서비스 영향·패치 전 백업 확인이 필요합니다.')
   start=max(now,body.not_before.astimezone(timezone.utc));end=start+timedelta(hours=2)
   c.execute("UPDATE defender_actions SET status='approved',approved=?,not_before=?,expires=? WHERE id=?",(s.now(),start.isoformat(),end.isoformat(),aid))
  s.audit('defender_approved',aid);return {'id':aid,'status':'approved'}
 @s.app.post('/api/defender/actions/{aid}/cancel')
 async def cancel(aid:str,body:Cancel,request:Request):
  s.admin(request)
  with s.db() as c:
   n=c.execute("UPDATE defender_actions SET status='cancelled',result=? WHERE id=? AND status IN ('proposed','approved')",(json.dumps({'detail':body.reason}),aid)).rowcount
   if not n:raise HTTPException(409,'실행 전 조치만 취소할 수 있습니다. 실행 중에는 중단하지 않습니다.')
  s.audit('defender_cancelled',aid);return {'status':'cancelled'}
 @s.app.post('/api/defender/actions/claim')
 async def claim(request:Request):
  d=s.token_device(request);now=s.now()
  with s.db() as c:
   c.execute('BEGIN IMMEDIATE')
   c.execute("UPDATE defender_actions SET status='expired' WHERE status='approved' AND expires<?",(now,))
   # A claimed action is never automatically retried: its outcome may be unknown.
   c.execute("UPDATE defender_actions SET status='outcome_unknown' WHERE status='claimed' AND claimed<?",((datetime.now(timezone.utc)-timedelta(hours=6)).isoformat(),))
   if c.execute("SELECT 1 FROM defender_actions WHERE device=? AND status='claimed'",(d['id'],)).fetchone():return {'action':None}
   r=c.execute("SELECT * FROM defender_actions WHERE device=? AND status='approved' AND not_before<=? AND expires>=? ORDER BY CASE WHEN kind='verify_action' THEN 0 ELSE 1 END,approved LIMIT 1",(d['id'],now,now)).fetchone()
   if not r:return {'action':None}
   if r['kind']!='verify_action' and c.execute("SELECT 1 FROM defender_actions WHERE device=? AND status='outcome_unknown'",(d['id'],)).fetchone():return {'action':None}
   token=secrets.token_urlsafe(48)
   c.execute("UPDATE defender_actions SET status='claimed',claim_hash=?,claimed=? WHERE id=?",(s.digest(token),now,r['id']))
  s.audit('defender_claimed',r['id']);return {'action':{'id':r['id'],'kind':r['kind'],'device':r['device'],'payload':json.loads(r['payload']),'claim':token,'expires':r['expires']}}
 @s.app.post('/api/defender/actions/{aid}/recheck')
 async def recheck(aid:str,request:Request):
  s.admin(request)
  with s.db() as c:
   r=c.execute('SELECT * FROM defender_actions WHERE id=?',(aid,)).fetchone()
   if not r or r['kind'] not in ('update_install','firewall_block','firewall_remove') or r['status'] in ('proposed','approved','claimed','cancelled','expired'):raise HTTPException(409,'실행 결과가 있는 조치만 다시 확인할 수 있습니다.')
   active(s,r['device'])
   payload={'original_id':aid,'original_kind':r['kind'],'original_payload':json.loads(r['payload'])}
   ident=str(uuid.uuid4());now=s.now()
   # Rechecks are read-only and can resolve an unknown execution outcome.
   if c.execute("SELECT 1 FROM defender_actions WHERE device=? AND kind='verify_action' AND target=? AND status IN ('approved','claimed')",(r['device'],aid)).fetchone():raise HTTPException(409,'재검증이 대기 중입니다.')
   c.execute('INSERT INTO defender_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(ident,r['device'],'verify_action',aid,'관리자 요청 읽기 전용 재검증','approved',now,now,now,(datetime.now(timezone.utc)+timedelta(hours=2)).isoformat(),None,None,json.dumps(payload),None))
  s.audit('defender_recheck',aid);return {'id':ident,'status':'approved'}
 @s.app.post('/api/defender/actions/{aid}/result')
 async def result(aid:str,body:Result,request:Request):
  d=s.token_device(request)
  with s.db() as c:
   r=c.execute('SELECT * FROM defender_actions WHERE id=? AND device=?',(aid,d['id'])).fetchone()
   if not r or not r['claim_hash'] or not secrets.compare_digest(r['claim_hash'],s.digest(body.claim)):raise HTTPException(403,'조치 실행 증명이 일치하지 않습니다.')
   if r['status'] not in ('claimed','outcome_unknown'):return {'status':r['status']}
   state='verified' if body.success and body.verified and not body.reboot_required else 'verification_needed' if body.success else 'failed'
   value=body.model_dump(exclude={'claim'});value['reported_at']=s.now()
   c.execute('UPDATE defender_actions SET status=?,result=? WHERE id=?',(state,json.dumps(value),aid))
   if r['kind']=='verify_action' and body.success and body.verified and not body.reboot_required:
    payload=json.loads(r['payload']);c.execute("UPDATE defender_actions SET status='verified',result=? WHERE id=? AND device=? AND status NOT IN ('proposed','approved','claimed','cancelled','expired')",(json.dumps(value),payload['original_id'],d['id']))
  s.audit('defender_result',aid);return {'status':state}
