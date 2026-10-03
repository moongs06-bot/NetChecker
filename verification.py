"""Persistent post-action checks; raw notes stay local, tool inputs are aggregate data."""
import asyncio,json,uuid
from datetime import datetime,timedelta,timezone
from fastapi import Request,HTTPException
from pydantic import BaseModel,Field,ConfigDict,field_validator
from typing import Literal
from network_analysis import metrics
from live_monitor import rows_for

class CheckRequest(BaseModel):
 model_config=ConfigDict(extra='forbid')
 report_id:str=Field(max_length=80)
 device_id:str=Field(max_length=80)
 action_kind:Literal['파일 전송 중단','백업 작업 조정','프로그램 종료','자원 확보','기타 조치']
 note:str=Field(default='',max_length=1000)
 action_at:datetime
 minutes:Literal[10,30,60]=10
 @field_validator('action_at')
 @classmethod
 def timestamp(cls,v):
  if v.tzinfo is None:raise ValueError('시간대가 필요합니다.')
  if not datetime.now(timezone.utc)-timedelta(days=29)<=v<=datetime.now(timezone.utc)+timedelta(minutes=1):raise ValueError('최근 29일 이내의 조치 시각을 입력하세요.')
  return v.astimezone(timezone.utc)
class Feedback(BaseModel):
 value:Literal['improved','still_slow','unknown']

def init(s):
 with s.db() as c:
  c.execute('CREATE TABLE IF NOT EXISTS verifications(id TEXT PRIMARY KEY,report_id TEXT,status TEXT,created TEXT,due TEXT,payload TEXT)')
  c.execute('CREATE INDEX IF NOT EXISTS verification_due ON verifications(status,due)')

def comparison(c,device,at,minutes):
 delta=timedelta(minutes=minutes);a=rows_for(c,device,at-delta,at);b=rows_for(c,device,at,at+delta)
 before=metrics(a,at-delta,at);after=metrics(b,at,at+delta);checks={}
 resource_quality=lambda rows:len({r['ts'][:16] for r in rows if json.loads(r['payload']).get('resource_collection_ok')})>=minutes*.8
 for metric,key in [('traffic','average_mbps'),('cpu','cpu_avg'),('ram','ram_avg')]:
  x,y=before[key],after[key];quality=min(before['coverage_percent'],after['coverage_percent'])>=80 and all(x['stale_seconds'] is not None and x['stale_seconds']<=180 for x in (before,after)) if metric=='traffic' else resource_quality(a) and resource_quality(b)
  comparable=quality and x is not None and y is not None and (x>0 if metric=='traffic' else True)
  improvement=comparable and (y<=x*.8 if metric=='traffic' else y<=x-10)
  worsened=comparable and (y>=x*1.2 if metric=='traffic' else y>=x+10)
  checks[metric]={'comparable':bool(comparable),'before':x,'after':y,'improved':bool(improvement),'worsened':bool(worsened),'change_percent':round((y-x)/x*100,2) if comparable and x else None}
 return {'device':device,'before':before,'after':after,'checks':checks,'before_start':(at-delta).isoformat(),'action_at':at.isoformat(),'after_end':(at+delta).isoformat()}

def build(s,p):
 at=datetime.fromisoformat(p['action_at'])
 with s.db() as c:
  target=comparison(c,p['device_id'],at,p['minutes']);fleet=[]
  devices=c.execute('SELECT id,role FROM devices WHERE active=1').fetchall()
  for d in devices:
   if d['id']==p['device_id']:continue
   item=comparison(c,d['id'],at,p['minutes']);item['role']=d['role'];fleet.append(item)
  parent=c.execute('SELECT payload FROM reports WHERE id=?',(p['report_id'],)).fetchone()
  previous=[{k:v for k,v in json.loads(r['payload']).items() if k in ('action_kind','action_at','feedback')} for r in c.execute('SELECT payload FROM verifications WHERE report_id=? AND id!=? ORDER BY created DESC LIMIT 5',(p['report_id'],p['id']))]
 old=json.loads(parent['payload']) if parent else {}
 fleet.sort(key=lambda d:-(d['after']['average_mbps'] or 0))
 return {'action_kind':p['action_kind'],'target':target,'fleet':fleet[:20],'context':{'prior_summary':old.get('summary','')[:3000],'prior_findings':[f for f in old.get('findings',[]) if f.get('device')==p['device_id']],'feedback':[f for f in previous if f],'note_policy':'담당자 자유 입력 메모는 외부 AI로 전송하지 않습니다.'}}

async def execute(s,ident):
 from agent_runner import investigate
 async with s.report_lock:
  with s.db() as c:r=c.execute('SELECT payload FROM verifications WHERE id=?',(ident,)).fetchone()
  p=json.loads(r['payload'])
  try:
   data=await asyncio.to_thread(build,s,p);p['comparison']=data['target']
   def progress(trace):
    p['trace']=trace
    with s.db() as c:c.execute('UPDATE verifications SET payload=? WHERE id=?',(json.dumps(p,ensure_ascii=False),ident))
   # Device IDs are already opaque. Exclude local free text and identifying labels/IPs.
   safe=s.server_analytics.safe(data,s.alias)
   output=await investigate(s.cfg(),{},p['action_at'][:10],s.STATE,mode='verification',progress=progress,analysis=safe)
   p['result']=output;p['trace']=output['trace'];state='done'
  except Exception as exc:
   p['error']='AI 개선 확인을 완료하지 못했습니다. 다시 확인을 요청해주세요.';p['error_type']=type(exc).__name__;state='failed'
  with s.db() as c:c.execute('UPDATE verifications SET status=?,payload=? WHERE id=?',(state,json.dumps(p,ensure_ascii=False),ident))

def dispatch(s):
 with s.db() as c:
  c.execute('BEGIN IMMEDIATE')
  if c.execute("SELECT 1 FROM reports WHERE status='running'").fetchone() or c.execute("SELECT 1 FROM verifications WHERE status='running'").fetchone():return
  r=c.execute("SELECT id FROM verifications WHERE status='waiting' AND due<=? ORDER BY due LIMIT 1",(s.now(),)).fetchone()
  if not r:return
  c.execute("UPDATE verifications SET status='running' WHERE id=?",(r['id'],))
 task=asyncio.create_task(execute(s,r['id']));s.tasks.add(task);task.add_done_callback(s.tasks.discard)

def install(s):
 @s.app.post('/api/verifications')
 async def create(body:CheckRequest,request:Request):
  s.admin(request);ident=str(uuid.uuid4());p=body.model_dump(mode='json');p.update(id=ident,trace=[]);due=body.action_at+timedelta(minutes=body.minutes,seconds=90)
  with s.db() as c:
   c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT status,payload FROM reports WHERE id=?',(body.report_id,)).fetchone()
   if not r or r['status']!='done' or json.loads(r['payload']).get('kind')!='network':raise HTTPException(400,'완료된 네트워크 분석을 선택해주세요.')
   if not c.execute('SELECT 1 FROM devices WHERE id=? AND active=1',(body.device_id,)).fetchone():raise HTTPException(400,'등록된 대상 장비를 선택해주세요.')
   if c.execute("SELECT 1 FROM verifications WHERE report_id=? AND status IN ('waiting','running')",(body.report_id,)).fetchone():raise HTTPException(409,'이 분석의 개선 확인이 이미 진행 중입니다.')
   if c.execute('SELECT count(*) FROM verifications WHERE created>=?',((datetime.now(timezone.utc)-timedelta(days=1)).isoformat(),)).fetchone()[0]>=20:raise HTTPException(429,'개선 확인은 24시간에 최대 20회입니다.')
   c.execute('INSERT INTO verifications VALUES(?,?,?,?,?,?)',(ident,body.report_id,'waiting',s.now(),due.isoformat(),json.dumps(p,ensure_ascii=False)))
  s.audit('verification_requested',ident);return {'id':ident,'status':'waiting','due':due.isoformat()}
 @s.app.get('/api/verifications')
 async def listing(request:Request,report_id:str):
  s.admin(request)
  with s.db() as c:return [{**dict(r),'payload':json.loads(r['payload'])} for r in c.execute('SELECT * FROM verifications WHERE report_id=? ORDER BY created DESC LIMIT 20',(report_id,))]
 @s.app.post('/api/verifications/{ident}/feedback')
 async def feedback(ident:str,body:Feedback,request:Request):
  s.admin(request)
  with s.db() as c:
   c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT status,payload FROM verifications WHERE id=?',(ident,)).fetchone()
   if not r or r['status']!='done':raise HTTPException(409,'완료된 개선 확인에 의견을 남길 수 있습니다.')
   p=json.loads(r['payload']);p['feedback']={'value':body.value,'at':s.now()};c.execute('UPDATE verifications SET payload=? WHERE id=?',(json.dumps(p,ensure_ascii=False),ident))
  s.audit('verification_feedback',ident);return {'ok':True}
