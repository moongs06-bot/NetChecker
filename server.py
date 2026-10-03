"""NetChecker pilot: authenticated telemetry intake and daily Agent investigations."""
import asyncio,base64,hashlib,hmac,ipaddress,json,os,secrets,sqlite3,time,uuid
from collections import defaultdict,deque
from functools import lru_cache
from contextlib import asynccontextmanager
from datetime import datetime,timedelta,timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from fastapi import FastAPI,Request,HTTPException
from fastapi.responses import HTMLResponse,FileResponse,Response
from pydantic import BaseModel,ConfigDict,Field,field_validator
from telemetry_models import FlowWindow,PortEvent,ServerPolicy
import server_analytics,network_analysis as network_policy
from display_utils import visible_ipv4,sanitize
from report_copy import present_report

ROOT=Path(__file__).parent
STATE=Path(os.getenv('NETCHECKER_STATE','./state'));STATE.mkdir(parents=True,exist_ok=True)
CONFIG=Path(os.getenv('NETCHECKER_CONFIG','./config.json'))
KST=ZoneInfo('Asia/Seoul'); UTC=timezone.utc
def cfg():
 import portal_auth,sys
 return portal_auth.credentials(sys.modules[__name__])
def now():return datetime.now(UTC).isoformat()
def db():
 c=sqlite3.connect(STATE/'netchecker.db',timeout=20);c.row_factory=sqlite3.Row
 c.execute('PRAGMA journal_mode=WAL');return c
def init():
 with db() as c:c.executescript('''
 CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,label TEXT,role TEXT,token_hash TEXT,active INTEGER,created TEXT,expected TEXT);
 CREATE TABLE IF NOT EXISTS samples(device TEXT,batch TEXT,ts TEXT,received TEXT,payload TEXT,PRIMARY KEY(device,batch));
 CREATE INDEX IF NOT EXISTS sample_time ON samples(ts); CREATE INDEX IF NOT EXISTS sample_device_time ON samples(device,ts);
 CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,day TEXT,status TEXT,created TEXT,payload TEXT);
 CREATE TABLE IF NOT EXISTS audit(ts TEXT,action TEXT,object TEXT);
 CREATE TABLE IF NOT EXISTS cleanup(session TEXT PRIMARY KEY);
 CREATE TABLE IF NOT EXISTS enrollment_requests(installation_id TEXT PRIMARY KEY,token_hash TEXT UNIQUE,hostname TEXT,ips TEXT,macs TEXT,os_name TEXT,source_ip TEXT,status TEXT,device_id TEXT,created TEXT,last_seen TEXT);
 CREATE TABLE IF NOT EXISTS flow_windows(device TEXT,window_id TEXT,ended_at TEXT,payload TEXT,PRIMARY KEY(device,window_id));
 CREATE INDEX IF NOT EXISTS flow_time ON flow_windows(device,ended_at);
 CREATE TABLE IF NOT EXISTS port_events(device TEXT,record_id TEXT,ts TEXT,payload TEXT,PRIMARY KEY(device,record_id,ts));
 CREATE INDEX IF NOT EXISTS port_time ON port_events(device,ts);
 CREATE TABLE IF NOT EXISTS server_policies(device TEXT PRIMARY KEY,payload TEXT);
 ''')
 import portal_auth,sys
 portal_auth.init(sys.modules[__name__])
 import verification
 verification.init(sys.modules[__name__])
 import agent_work_logs
 agent_work_logs.init(sys.modules[__name__])
 import integrations
 integrations.init(sys.modules[__name__])
 import security_defender
 security_defender.init(sys.modules[__name__])
 with db() as c:c.execute('CREATE TABLE IF NOT EXISTS device_list_hidden(device TEXT PRIMARY KEY,hidden_at TEXT)')

def audit(action,ident):
 with db() as c:c.execute('INSERT INTO audit VALUES(?,?,?)',(now(),action,ident))
def digest(value):return hashlib.sha256(value.encode()).hexdigest()
attempts=defaultdict(deque)
def budget(key,n,seconds):
 q=attempts[key];t=time.monotonic()
 while q and q[0]<t-seconds:q.popleft()
 if len(q)>=n:raise HTTPException(429,'잠시 뒤 다시 시도하세요.')
 q.append(t)
def admin(request):
 import portal_auth,sys
 return portal_auth.guard(sys.modules[__name__],request)

def token_device(request):
 value=request.headers.get('authorization','')
 if not value.startswith('Bearer '):raise HTTPException(401,'장비 인증 필요')
 with db() as c:row=c.execute('SELECT * FROM devices WHERE active=1 AND token_hash=?',(digest(value[7:]),)).fetchone()
 if not row:raise HTTPException(401,'등록 키가 올바르지 않습니다.')
 budget('ingest:'+row['id'],6,60);return dict(row)

class Strict(BaseModel):model_config=ConfigDict(extra='forbid',allow_inf_nan=False)
class Connection(Strict):
 remote_ip:str=Field(max_length=45)
 remote_port:int=Field(ge=1,le=65535)
 local_ip:str|None=None
 local_port:int|None=Field(default=None,ge=1,le=65535)
 process:str=Field(max_length=100)
 state:str=Field(max_length=24)
 @field_validator('remote_ip')
 @classmethod
 def ip(cls,v):return str(ipaddress.ip_address(v))
class Sample(Strict):
 flow_window:FlowWindow|None=None
 flow_status:str=Field(default='not_collected',pattern='^(running|unavailable|not_collected|waiting)$')
 port_events:list[PortEvent]=Field(default_factory=list,max_length=100)
 port_status:str=Field(default='not_collected',pattern='^(not_collected|readable_policy_unverified|unavailable|truncated)$')
 batch_id:uuid.UUID
 observed_at:datetime
 interval_seconds:float=Field(ge=0,le=3600)
 tx_bytes:int=Field(ge=0,le=10**13)
 rx_bytes:int=Field(ge=0,le=10**13)
 counter_valid:bool
 cpu_percent:float=Field(ge=0,le=100)
 memory_percent:float=Field(ge=0,le=100)
 disk_percent:float=Field(ge=0,le=100)
 connections:list[Connection]=Field(max_length=500)
 connections_total:int=Field(ge=0,le=1000000)
 connection_collection_ok:bool
 resource_collection_ok:bool
 collector_version:str=Field(max_length=30)
 @field_validator('observed_at')
 @classmethod
 def date(cls,v):
  if v.tzinfo is None:raise ValueError('timezone required')
  if not datetime.now(UTC)-timedelta(days=2)<=v<=datetime.now(UTC)+timedelta(minutes=5):raise ValueError('collection timestamp outside accepted range')
  return v.astimezone(UTC)
class Enrollment(Strict):
 label:str=Field(min_length=1,max_length=60)
 role:str=Field(pattern='^(pc|ad|erp|plm|other)$')
class Registration(Strict):
 installation_id:uuid.UUID
 token:str=Field(min_length=40,max_length=100,pattern=r'^[A-Za-z0-9_-]+$')
 hostname:str=Field(min_length=1,max_length=100)
 ips:list[str]=Field(max_length=32)
 macs:list[str]=Field(max_length=32)
 os_name:str=Field(max_length=150)
 @field_validator('ips')
 @classmethod
 def addresses(cls,v):return sorted(set(str(ipaddress.ip_address(x)) for x in v))
 @field_validator('macs')
 @classmethod
 def mac_addresses(cls,v):
  import re
  result=[]
  for item in v:
   cleaned=item.replace(':','').replace('-','').upper()
   if not re.fullmatch(r'[0-9A-F]{12}',cleaned):raise ValueError('Invalid MAC address')
   result.append(':'.join(cleaned[i:i+2] for i in range(0,12,2)))
  return sorted(set(result))
class Expected(Strict):
 backup_hours:list[int]=Field(max_length=24)
 maintenance_hours:list[int]=Field(max_length=24)
 @field_validator('backup_hours','maintenance_hours')
 @classmethod
 def hours(cls,v):
  if any(type(x)!=int or not 0<=x<=23 for x in v):raise ValueError('0-23 hours required')
  return sorted(set(v))
class ReportRequest(Strict):day:str=Field(pattern=r'^\d{4}-\d{2}-\d{2}$')
class NetworkRequest(Strict):minutes:int=Field(default=30,ge=5,le=120)

def period(day):
 start=datetime.strptime(day,'%Y-%m-%d').replace(tzinfo=KST)
 if start.date()>datetime.now(KST).date() or start.date()<datetime.now(KST).date()-timedelta(days=30):raise ValueError('최근 30일의 날짜를 선택하세요.')
 return start.astimezone(UTC),(start+timedelta(days=1)).astimezone(UTC)
@lru_cache(maxsize=32768)
def alias(kind,value):return kind+'-'+hmac.new(cfg()['alias_secret'].encode(),value.encode(),hashlib.sha256).hexdigest()[:12]
def summary(rows,excluded=frozenset()):
 timeline=[];truncated=0;peak_tx=peak_rx=0
 tx=rx=0;hours=defaultdict(int);dest=defaultdict(int);proc=defaultdict(int);maxcpu=maxmem=maxdisk=0;seconds=0;errors=0;resources_missing=0
 for row in rows:
  p=json.loads(row['payload']);hour=str(datetime.fromisoformat(row['ts']).astimezone(KST).hour)
  truncated+=p['connections_total']>len(p['connections'])
  if p['counter_valid'] and p['interval_seconds']>0:
   tx_rate=round(p['tx_bytes']*8/p['interval_seconds']/1000000,3);rx_rate=round(p['rx_bytes']*8/p['interval_seconds']/1000000,3)
   peak_tx=max(peak_tx,tx_rate);peak_rx=max(peak_rx,rx_rate)
   timeline.append({'time':row['ts'],'tx_mbps':tx_rate,'rx_mbps':rx_rate,'connections':p['connections_total'],'cpu':p['cpu_percent'] if p['resource_collection_ok'] else None})
  if p['counter_valid']:tx+=p['tx_bytes'];rx+=p['rx_bytes'];seconds+=p['interval_seconds'];hours[hour]+=p['tx_bytes']
  errors+=not p['connection_collection_ok'];resources_missing+=not p['resource_collection_ok']
  if p['resource_collection_ok']:maxcpu=max(maxcpu,p['cpu_percent']);maxmem=max(maxmem,p['memory_percent']);maxdisk=max(maxdisk,p['disk_percent'])
  for connection in p['connections']:
   if connection['remote_ip'] in excluded:continue
   addr=ipaddress.ip_address(connection['remote_ip']);key=(alias('dst',str(addr)),'private' if addr.is_private else 'public',connection['remote_port'])
   dest[key]+=1;proc[alias('process',connection['process'])]+=1
 return {'samples':len(rows),'covered_seconds':round(seconds),'tx_bytes':tx,'rx_bytes':rx,'peak_tx_mbps':peak_tx,'peak_rx_mbps':peak_rx,'recent_intervals':timeline[-120:],'truncated_connection_samples':truncated,'max_cpu':maxcpu if rows and resources_missing<len(rows) else None,'max_memory':maxmem if rows and resources_missing<len(rows) else None,'max_disk':maxdisk if rows and resources_missing<len(rows) else None,'connection_errors':errors,'resource_errors':resources_missing,'hourly_tx':dict(hours),'destinations':[{'destination':k[0],'scope':k[1],'port':k[2],'snapshot_occurrences':v} for k,v in sorted(dest.items(),key=lambda x:-x[1])[:30]],'processes':[{'process':k,'snapshot_occurrences':v} for k,v in sorted(proc.items(),key=lambda x:-x[1])[:20]]}
def snapshot(day,minutes=None,end_at=None):
 start,end=period(day);result={}
 if minutes:
  end=end_at or datetime.now(UTC);start=end-timedelta(minutes=minutes)
 with db() as c:
  for d in c.execute('SELECT * FROM devices WHERE active=1').fetchall():
   rows=c.execute('SELECT ts,payload FROM samples WHERE device=? AND ts>=? AND ts<? ORDER BY ts',(d['id'],start.isoformat(),end.isoformat())).fetchall()
   history=c.execute('SELECT ts,payload FROM samples WHERE device=? AND ts>=? AND ts<? ORDER BY ts',(d['id'],(start-(timedelta(hours=6) if minutes else timedelta(days=7))).isoformat(),start.isoformat())).fetchall()
   excluded=server_analytics.plm_ips(c) if d['role']=='plm' else set()
   current=summary(rows,excluded);baseline=summary(history,excluded)
   if excluded:current['exclusion_note']='PLM 서버 간 및 자체 연결은 목적지 조사에서 제외했습니다. 전체 NIC 통신량과 자원 지표에는 정상 PLM 통신이 포함되므로 이를 단독으로 이상 통신이라 판단하지 마세요.'
   baseline.pop('recent_intervals',None)
   result[d['id']]={'device':d['id'],'role':d['role'],'window_start':start.isoformat(),'window_end':end.isoformat(),'last_seen':rows[-1]['ts'] if rows else None,'current':current,'baseline':baseline,'baseline_days':len({datetime.fromisoformat(r['ts']).astimezone(KST).date() for r in history}),'expected':json.loads(d['expected'])}
 return result

report_lock=asyncio.Lock()
async def execute_report(rid,day,minutes=None,end_at=None):
 async with report_lock:
  from agent_runner import investigate
  context={};kind='network' if minutes else 'daily'
  try:
   anchor=end_at or datetime.now(UTC)
   data=snapshot(day,minutes,anchor)
   if minutes:
    with db() as c:layout=network_policy.build(c,minutes,anchor)
    context={'network_report':layout,'kind':kind,'minutes':minutes}
    safe_layout={'network_report':server_analytics.safe(layout,alias)}
   else:
    start,end=period(day)
    with db() as c:layout=server_analytics.build(c,day,start,end)
    context={'server_report':layout,'kind':kind,'minutes':None}
    safe_layout=server_analytics.safe(layout,alias)
   with db() as c:c.execute('UPDATE reports SET payload=? WHERE id=?',(json.dumps({**context,'summary':'비교 집계 완료 · Agent가 근거를 조사하고 있습니다.','trace':[]},ensure_ascii=False),rid))
   import integrations,sys
   try:external=await asyncio.wait_for(integrations.context(sys.modules[__name__],day),timeout=25)
   except Exception:external={'date':day,'note':'외부 공공데이터 조회를 완료하지 못했습니다. 판단에 사용하지 마세요.'}
   context['external_context']=external;safe_layout['external_context']=external
   if kind=='daily':
    import defender_daily,sys
    context['defender_daily']=await defender_daily.build(sys.modules[__name__],day)
   if not any(x['current']['samples'] for x in data.values()):
    output={'summary':'최근 수집 데이터가 없어 판단할 수 없습니다.','findings':[],'trace':[],'limitations':['최근 데이터 미수집'],'mode':'no_data'}
   else:output=await investigate(cfg(),data,day,STATE,mode=kind,progress=lambda trace:save_progress(rid,trace),analysis=safe_layout)
   if kind=='daily' and output.get('mode')!='no_data':
    from daily_crew import review_daily
    output=await review_daily(cfg(),output,day,progress=lambda trace:save_progress(rid,trace),analysis=safe_layout)
   elif kind=='daily':
    output['daily_crew']={'status':'skipped','reason':'수집된 자료가 없어 분석·검증을 진행하지 않았습니다.'}
    output['priority_checks']=[]
   output.update(context);status='failed' if output.get('daily_crew',{}).get('status')=='failed' or context.get('defender_daily',{}).get('status')=='failed' else 'done'
  except Exception as exc:
   with db() as c:previous=c.execute('SELECT payload FROM reports WHERE id=?',(rid,)).fetchone()
   old=json.loads(previous['payload']) if previous else {}
   status='failed';output={**old,**context,'summary':'Agent 분석을 완료하지 못했습니다. 집계 순위는 확인할 수 있으며 AI 해석은 미완료입니다.','error_type':type(exc).__name__,'findings':[],'trace':old.get('trace',[]),'mode':'failed','kind':kind,'minutes':minutes}
  with db() as c:c.execute('UPDATE reports SET status=?,payload=? WHERE id=?',(status,json.dumps(output,ensure_ascii=False),rid))
  try:
   import integrations,sys
   await integrations.send(sys.modules[__name__],rid,day,status)
  except Exception:pass

def save_progress(rid,trace):
 with db() as c:
  row=c.execute('SELECT payload FROM reports WHERE id=?',(rid,)).fetchone()
  old=json.loads(row['payload']) if row else {}
  c.execute('UPDATE reports SET payload=? WHERE id=?',(json.dumps({**old,'summary':'Agent가 수집 자료를 조사 중입니다.','trace':trace},ensure_ascii=False),rid))

def enqueue(day,minutes=None):
 period(day)
 with db() as c:
  c.execute('BEGIN IMMEDIATE')
  if c.execute("SELECT count(*) FROM reports WHERE status='running'").fetchone()[0] or c.execute("SELECT count(*) FROM verifications WHERE status='running'").fetchone()[0]:raise HTTPException(409,'다른 분석이 진행 중입니다.')
  if c.execute('SELECT count(*) FROM reports WHERE created>=?',(datetime.now(UTC).replace(hour=0,minute=0,second=0,microsecond=0).isoformat(),)).fetchone()[0]>=20:raise HTTPException(429,'시범 운영은 하루 최대 20회 분석합니다.')
  rid=str(uuid.uuid4());anchor=datetime.now(UTC);initial={'kind':'network' if minutes else 'daily','minutes':minutes,'window_end':anchor.isoformat() if minutes else None,'trace':[]};c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',(rid,day,'running',anchor.isoformat(),json.dumps(initial)))
 task=asyncio.create_task(execute_report(rid,day,minutes,anchor));tasks.add(task);task.add_done_callback(tasks.discard)
 return rid
tasks=set()
async def schedule():
 while True:
  try:
   import verification,sys
   verification.dispatch(sys.modules[__name__])
   local=datetime.now(KST);day=(local-timedelta(days=1)).date().isoformat()
   if local.hour>=8:
    with db() as c:exists=c.execute("SELECT 1 FROM reports WHERE day=? AND COALESCE(json_extract(payload,'$.kind'),'daily')='daily' AND NOT EXISTS(SELECT 1 FROM audit a WHERE a.action='report' AND a.object=reports.id)",(day,)).fetchone()
    if not exists:enqueue(day)
   with db() as c:
    cutoff=(datetime.now(UTC)-timedelta(days=30)).isoformat()
    c.execute('DELETE FROM samples WHERE ts<?',(cutoff,));c.execute('DELETE FROM flow_windows WHERE ended_at<?',(cutoff,));c.execute('DELETE FROM port_events WHERE ts<?',(cutoff,))
    c.execute('DELETE FROM defender_events WHERE ts<?',(cutoff,))
  except Exception:pass
  await asyncio.sleep(60)
@asynccontextmanager
async def lifespan(app):
 init()
 with db() as c:
  for row in c.execute("SELECT id,payload FROM reports WHERE status='running'").fetchall():
   old=json.loads(row['payload']);old.update(summary='서버 재시작으로 분석 중단',findings=[],mode='failed')
   c.execute("UPDATE reports SET status='failed',payload=? WHERE id=?",(json.dumps(old,ensure_ascii=False),row['id']))
 with db() as c:c.execute("UPDATE verifications SET status='failed',payload=json_set(payload,'$.error','서버 재시작으로 개선 확인이 중단됐습니다. 다시 요청해주세요.') WHERE status='running'")
 worker=asyncio.create_task(schedule())
 yield
 worker.cancel()
 for task in list(tasks):task.cancel()
 await asyncio.gather(worker,*tasks,return_exceptions=True)
app=FastAPI(lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
@app.middleware('http')
async def headers(request,call_next):
 try:
  if int(request.headers.get('content-length','0'))>300000: return Response(status_code=413)
 except ValueError:return Response(status_code=400)
 response=await call_next(request);response.headers['Cache-Control']='no-store';response.headers['X-Content-Type-Options']='nosniff';response.headers['X-Frame-Options']='DENY';response.headers['Referrer-Policy']='no-referrer';return response
@app.get('/healthz')
async def health():return {'ok':True}
@app.get('/',response_class=HTMLResponse)
async def home(request:Request):
 try:admin(request)
 except HTTPException as exc:
  if exc.status_code!=401:raise
  return (ROOT/'login.html').read_text(encoding='utf-8')
 return (ROOT/'dashboard.html').read_text(encoding='utf-8')
@app.post('/api/ingest')
async def ingest(body:Sample,request:Request):
 d=token_device(request)
 with db() as c:
  c.execute('INSERT OR IGNORE INTO samples VALUES(?,?,?,?,?)',(d['id'],str(body.batch_id),body.observed_at.isoformat(),now(),body.model_dump_json()))
  if body.flow_window:
   w=body.flow_window;c.execute('INSERT OR IGNORE INTO flow_windows VALUES(?,?,?,?)',(d['id'],str(w.window_id),w.ended_at.isoformat(),w.model_dump_json()))
  for e in body.port_events:c.execute('INSERT OR IGNORE INTO port_events VALUES(?,?,?,?)',(d['id'],e.record_id,e.time.isoformat(),e.model_dump_json()))
 return {'ok':True,'device_id':d['id']}
@app.post('/api/devices')
async def enroll(body:Enrollment,request:Request):
 admin(request);key=secrets.token_urlsafe(32);ident='pc-'+secrets.token_hex(6)
 with db() as c:
  c.execute('BEGIN IMMEDIATE')
  c.execute('INSERT INTO devices VALUES(?,?,?,?,?,?,?)',(ident,body.label,body.role,digest(key),1,now(),json.dumps({'backup_hours':[],'maintenance_hours':[]})))
 audit('enroll',ident);return {'id':ident,'token':key,'message':'등록 키는 지금 한 번만 표시됩니다.'}
@app.post('/api/enrollment/request')
async def request_enrollment(body:Registration,request:Request):
 ident=str(body.installation_id);hashed=digest(body.token)
 budget('registration:'+request.client.host,120,60)
 with db() as c:
  c.execute('BEGIN IMMEDIATE')
  row=c.execute('SELECT * FROM enrollment_requests WHERE installation_id=?',(ident,)).fetchone()
  if row:
   if not hmac.compare_digest(row['token_hash'],hashed):raise HTTPException(403,'장비 인증 실패')
   c.execute('UPDATE enrollment_requests SET hostname=?,ips=?,macs=?,os_name=?,source_ip=?,last_seen=? WHERE installation_id=?',(body.hostname,json.dumps(body.ips),json.dumps(body.macs),body.os_name,request.client.host,now(),ident))
   state=row['status']
   if state=='approved':
    device=c.execute('SELECT active FROM devices WHERE id=?',(row['device_id'],)).fetchone()
    if not device or not device['active']:state='rejected'
   return {'status':state,'device_id':row['device_id'] if state=='approved' else None}
  budget('new-registration:'+request.client.host,15,3600)
  if c.execute("SELECT count(*) FROM enrollment_requests WHERE status='pending'").fetchone()[0]>=100:raise HTTPException(429,'등록 대기 목록 확인이 필요합니다.')
  if c.execute('SELECT 1 FROM enrollment_requests WHERE token_hash=?',(hashed,)).fetchone() or c.execute('SELECT 1 FROM devices WHERE token_hash=?',(hashed,)).fetchone():raise HTTPException(409,'이미 사용 중인 장비 키')
  c.execute('INSERT INTO enrollment_requests VALUES(?,?,?,?,?,?,?,?,?,?,?)',(ident,hashed,body.hostname,json.dumps(body.ips),json.dumps(body.macs),body.os_name,request.client.host,'pending',None,now(),now()))
 audit('registration_requested',ident)
 return {'status':'pending','device_id':None}
@app.post('/api/enrollment/{ident}/approve')
async def approve_enrollment(ident:str,body:Enrollment,request:Request):
 admin(request)
 with db() as c:
  c.execute('BEGIN IMMEDIATE')
  row=c.execute('SELECT * FROM enrollment_requests WHERE installation_id=?',(ident,)).fetchone()
  if not row:raise HTTPException(404,'등록 요청 없음')
  if row['status']=='approved':return {'id':row['device_id'],'status':'approved'}
  if row['status']!='pending':raise HTTPException(409,'승인 가능한 요청이 아닙니다.')
  device='pc-'+secrets.token_hex(6)
  c.execute('INSERT INTO devices VALUES(?,?,?,?,?,?,?)',(device,body.label,body.role,row['token_hash'],1,now(),json.dumps({'backup_hours':[],'maintenance_hours':[]})))
  c.execute("UPDATE enrollment_requests SET status='approved',device_id=? WHERE installation_id=?",(device,ident))
 audit('registration_approved',ident)
 return {'id':device,'status':'approved'}
@app.post('/api/enrollment/{ident}/reject')
async def reject_enrollment(ident:str,request:Request):
 admin(request)
 with db() as c:
  changed=c.execute("UPDATE enrollment_requests SET status='rejected' WHERE installation_id=? AND status='pending'",(ident,)).rowcount
  if not changed:raise HTTPException(409,'등록 대기 상태가 아닙니다.')
 audit('registration_rejected',ident);return {'status':'rejected'}
@app.put('/api/devices/{ident}/expected')
async def expected(ident:str,body:Expected,request:Request):
 admin(request)
 with db() as c:c.execute('UPDATE devices SET expected=? WHERE id=?',(body.model_dump_json(),ident))
 audit('expected_activity',ident);return {'ok':True}
@app.delete('/api/devices/{ident}')
async def revoke(ident:str,request:Request):
 admin(request)
 with db() as c:c.execute('UPDATE devices SET active=0 WHERE id=?',(ident,))
 audit('revoke',ident);return {'ok':True}
@app.get('/api/status')
async def status(request:Request):
 admin(request)
 with db() as c:
  devices=[dict(x) for x in c.execute('SELECT d.id,d.label,d.role,d.active,d.expected,q.hostname,q.ips,q.macs,q.os_name,(SELECT MAX(ts) FROM samples WHERE device=d.id) last_seen FROM devices d LEFT JOIN enrollment_requests q ON q.device_id=d.id WHERE NOT EXISTS(SELECT 1 FROM device_list_hidden h WHERE h.device=d.id) ORDER BY d.created')]
  pending=[dict(x) for x in c.execute("SELECT installation_id,hostname,ips,macs,os_name,source_ip,created,last_seen FROM enrollment_requests WHERE status='pending' ORDER BY created")]
  reports=[dict(x) for x in c.execute("SELECT id,day,status,created,json_extract(payload,'$.kind') kind,json_extract(payload,'$.minutes') minutes,CASE WHEN EXISTS(SELECT 1 FROM audit a WHERE a.action='report' AND a.object=reports.id) THEN 'manual' ELSE 'automatic' END AS trigger FROM reports WHERE status!='deleted' ORDER BY created DESC LIMIT 30")]
 for d in devices+pending:d['ips']=json.dumps(visible_ipv4(json.loads(d['ips'] or '[]')))
 return {'devices':devices,'pending':pending,'reports':reports,'schedule':'매일 오전 8시 KST · 전날 자료','retention_days':30}
@app.post('/api/reports')
async def create_report(body:ReportRequest,request:Request):
 admin(request)
 try:rid=enqueue(body.day)
 except ValueError as e:raise HTTPException(422,str(e))
 audit('report',rid);return {'id':rid}
@app.get('/api/traffic-ranking')
async def traffic_ranking(request:Request,hours:int=1):
 admin(request)
 from live_monitor import get_ranking,HOURS
 if hours not in HOURS:raise HTTPException(422,'1·2·4·6·8·12·24시간 중 선택해주세요.')
 value=await asyncio.to_thread(get_ranking,STATE/'netchecker.db',hours)
 return Response(json.dumps(value,ensure_ascii=False),media_type='application/json',headers={'Cache-Control':'no-store'})
@app.get('/api/live-monitor')
async def live_monitor_data(request:Request):
 admin(request)
 from live_monitor import get_snapshot
 value=await asyncio.to_thread(get_snapshot,STATE/'netchecker.db')
 return Response(json.dumps(value,ensure_ascii=False),media_type='application/json',headers={'Cache-Control':'no-store'})
@app.get('/live-monitor.js')
async def live_monitor_script(request:Request):
 admin(request)
 return FileResponse(ROOT/'live-monitor.js',media_type='application/javascript',headers={'Cache-Control':'no-cache'})
@app.get('/live-monitor.css')
async def live_monitor_style(request:Request):
 admin(request)
 return FileResponse(ROOT/'live-monitor.css',media_type='text/css',headers={'Cache-Control':'no-cache'})
@app.get('/api/traffic')
async def traffic(request:Request):
 admin(request)
 day=datetime.now(KST).date().isoformat();start,end=period(day)
 totals={'tx_bytes':0,'rx_bytes':0,'total_bytes':0};devices=[]
 with db() as c:
  for d in c.execute('SELECT id,label,role FROM devices WHERE active=1 ORDER BY label').fetchall():
   tx=rx=0;seconds=0;valid=0
   rows=c.execute('SELECT payload FROM samples WHERE device=? AND ts>=? AND ts<?',(d['id'],start.isoformat(),end.isoformat())).fetchall()
   for row in rows:
    p=json.loads(row['payload'])
    if p['counter_valid'] and p['interval_seconds']>0:
     tx+=p['tx_bytes'];rx+=p['rx_bytes'];seconds+=p['interval_seconds'];valid+=1
   devices.append({**dict(d),'tx_bytes':tx,'rx_bytes':rx,'total_bytes':tx+rx,'covered_seconds':round(seconds),'valid_samples':valid})
   totals['tx_bytes']+=tx;totals['rx_bytes']+=rx
 totals['total_bytes']=totals['tx_bytes']+totals['rx_bytes']
 return {'day':day,'timezone':'Asia/Seoul','scope':'internet_and_internal_network','totals':totals,'devices':sorted(devices,key=lambda d:-d['total_bytes'])}
@app.get('/api/server-overview')
async def server_overview(request:Request,day:str|None=None,hours:int|None=None,ip:str=''):
 admin(request);day=day or datetime.now(KST).date().isoformat()
 if len(ip)>45 or any(ch not in '0123456789.:abcdefABCDEF' for ch in ip):raise HTTPException(422,'검색할 IP 주소를 확인해주세요.')
 if hours is not None:
  if hours not in (0,1,2,4,6,8,12,24):raise HTTPException(422,'조회 기간을 확인해주세요.')
  end=datetime.now(UTC);start=end-timedelta(hours=hours) if hours else end-timedelta(minutes=5)
 else:
  try:start,end=period(day)
  except ValueError:raise HTTPException(422,'날짜를 확인하세요.')
 def load():
  with db() as c:return sanitize(server_analytics.build(c,day,start,end,search=ip,rolling=hours is not None,include_clients=True))
 return await asyncio.to_thread(load)
@app.put('/api/devices/{ident}/policy')
async def server_policy(ident:str,body:ServerPolicy,request:Request):
 admin(request)
 with db() as c:
  row=c.execute('SELECT role FROM devices WHERE id=? AND active=1',(ident,)).fetchone()
  if not row or row['role'] not in server_analytics.ROLES:raise HTTPException(400,'등록된 서버를 선택하세요.')
  c.execute('INSERT INTO server_policies VALUES(?,?) ON CONFLICT(device) DO UPDATE SET payload=excluded.payload',(ident,body.model_dump_json()))
 audit('server_policy',ident);return {'ok':True}
@app.put('/api/devices/{ident}/identity')
async def device_identity(ident:str,body:Enrollment,request:Request):
 admin(request)
 with db() as c:
  changed=c.execute('UPDATE devices SET label=?,role=? WHERE id=? AND active=1',(body.label,body.role,ident)).rowcount
  if not changed:raise HTTPException(404)
 audit('device_identity',ident);return {'ok':True}
@app.post('/api/network-analysis')
async def network_analysis(body:NetworkRequest,request:Request):
 admin(request)
 rid=enqueue(datetime.now(KST).date().isoformat(),body.minutes)
 audit('network_analysis',rid);return {'id':rid}
@app.delete('/api/reports/{rid}')
async def delete_report(rid:str,request:Request):
 admin(request)
 with db() as c:
  c.execute('BEGIN IMMEDIATE')
  row=c.execute('SELECT status,payload FROM reports WHERE id=?',(rid,)).fetchone()
  if not row or row['status']=='deleted':raise HTTPException(404,'삭제되었거나 존재하지 않는 분석입니다.')
  if row['status']=='running' or c.execute("SELECT 1 FROM verifications WHERE report_id=? AND status='running'",(rid,)).fetchone():raise HTTPException(409,'분석 또는 개선 확인이 진행 중입니다. 완료 후 삭제해주세요.')
  c.execute('DELETE FROM verifications WHERE report_id=?',(rid,))
  kind=json.loads(row['payload']).get('kind','daily')
  # Keep only scheduling/quota metadata; erase the report, evidence and trace.
  c.execute("UPDATE reports SET status='deleted',payload=? WHERE id=?",(json.dumps({'kind':kind}),rid))
  c.execute('INSERT INTO audit VALUES(?,?,?)',(now(),'report_deleted',rid))
 return {'id':rid,'deleted':True}
@app.get('/api/reports/{rid}')
async def report(rid:str,request:Request):
 admin(request)
 with db() as c:r=c.execute('SELECT * FROM reports WHERE id=?',(rid,)).fetchone()
 if not r or r['status']=='deleted':raise HTTPException(404,'삭제되었거나 존재하지 않는 분석입니다.')
 return present_report({**dict(r),'payload':json.loads(r['payload'])})
@app.get('/api/reports/{rid}/log')
async def report_log(rid:str,request:Request):
 value=await report(rid,request)
 return Response(json.dumps(value,ensure_ascii=False,indent=2),media_type='application/json',headers={'Content-Disposition':'attachment; filename="netchecker-investigation.json"'})
@app.get('/api/reports/{rid}/pdf')
async def report_pdf(rid:str,request:Request):
 value=await report(rid,request)
 if value['status']=='running':raise HTTPException(409,'분석 완료 후 PDF를 내려받을 수 있습니다.')
 with db() as c:labels={r['id']:r['label'] for r in c.execute('SELECT id,label FROM devices')}
 from pdf_report import build_report
 content=await asyncio.to_thread(build_report,value,labels)
 return Response(content,media_type='application/pdf',headers={'Content-Disposition':'attachment; filename="NetChecker-'+value['day']+'-'+value['id'][:8]+'.pdf"'})
@app.get('/downloads/{name}')
async def download(name:str,request:Request):
 admin(request)
 if name in ('NetChecker-Setup.exe','NetChecker-Server-Setup.exe','NetChecker-Defender-Setup.exe'):return FileResponse(ROOT/name,filename=name,media_type='application/octet-stream')
 if name not in ('Install-NetChecker.ps1','Collector.ps1','Uninstall-NetChecker.ps1','Read-PortEvents.ps1','flow.zip'):raise HTTPException(404)
 return FileResponse(ROOT/'collector'/name,filename=name)

import portal_auth,sys
portal_auth.install(sys.modules[__name__])

import verification
verification.install(sys.modules[__name__])

@app.get('/api/agent-work-logs')
async def agent_work_history(request:Request,day:str,offset:int=0):
 admin(request)
 import agent_work_logs,sys
 return agent_work_logs.listing(sys.modules[__name__],day,offset)

import integrations,sys
integrations.register(sys.modules[__name__])

import security_defender
security_defender.install(sys.modules[__name__])

@app.delete('/api/devices/{ident}/list')
async def hide_revoked_device(ident:str,request:Request):
 admin(request)
 with db() as c:
  row=c.execute('SELECT active FROM devices WHERE id=?',(ident,)).fetchone()
  if not row:raise HTTPException(404,'장비가 없습니다.')
  if row['active']:raise HTTPException(409,'등록 해제된 장비만 목록에서 삭제할 수 있습니다.')
  c.execute('INSERT OR IGNORE INTO device_list_hidden VALUES(?,?)',(ident,now()))
 audit('hide_revoked_device',ident);return {'ok':True}
