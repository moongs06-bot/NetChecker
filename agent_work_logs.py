"""Durable run logs independent of report deletion."""
import json
from datetime import datetime,timedelta,timezone
from fastapi import HTTPException
from report_copy import summarize_trace

def init(s):
 with s.db() as c:
  c.execute('CREATE TABLE IF NOT EXISTS agent_work_logs(id TEXT PRIMARY KEY,source TEXT,created TEXT,status TEXT,payload TEXT,updated TEXT)')
  c.execute('CREATE INDEX IF NOT EXISTS agent_work_date ON agent_work_logs(created)')
  for table in ('reports','verifications'):
   payload="json_object('kind',json_extract(NEW.payload,'$.kind'),'minutes',json_extract(NEW.payload,'$.minutes'),'trace',json(COALESCE(json_extract(NEW.payload,'$.trace'),'[]')),'summary',json_extract(NEW.payload,'$.summary'),'error',json_extract(NEW.payload,'$.error'))"
   for event in ('INSERT','UPDATE'):
    c.execute(f"CREATE TRIGGER IF NOT EXISTS archive_{table}_{event.lower()} AFTER {event} ON {table} WHEN NEW.status!='deleted' BEGIN INSERT INTO agent_work_logs VALUES('{table}:'||NEW.id,'{table}',NEW.created,NEW.status,{payload},strftime('%Y-%m-%dT%H:%M:%f+00:00','now')) ON CONFLICT(id) DO UPDATE SET status=excluded.status,payload=excluded.payload,updated=excluded.updated; END")
   c.execute(f"INSERT OR IGNORE INTO agent_work_logs SELECT '{table}:'||id,'{table}',created,status,json_object('kind',json_extract(payload,'$.kind'),'minutes',json_extract(payload,'$.minutes'),'trace',json(COALESCE(json_extract(payload,'$.trace'),'[]')),'summary',json_extract(payload,'$.summary'),'error',json_extract(payload,'$.error')),created FROM {table} WHERE status!='deleted'")

def listing(s,day,offset):
 try:start=datetime.strptime(day,'%Y-%m-%d').replace(tzinfo=s.KST).astimezone(timezone.utc)
 except ValueError:raise HTTPException(400,'날짜 형식을 확인해 주세요.')
 if offset<0:raise HTTPException(400,'조회 위치 오류')
 end=start+timedelta(days=1)
 with s.db() as c:
  total=c.execute('SELECT count(*) FROM agent_work_logs WHERE created>=? AND created<?',(start.isoformat(),end.isoformat())).fetchone()[0]
  rows=c.execute('SELECT * FROM agent_work_logs WHERE created>=? AND created<? ORDER BY created DESC,id LIMIT 50 OFFSET ?',(start.isoformat(),end.isoformat(),offset)).fetchall()
 result=[]
 for r in rows:
  p=json.loads(r['payload']);title='조치 후 개선 확인' if r['source']=='verifications' else '네트워크 지연 Agent 분석 (최근 '+str(p.get('minutes') or '')+'분)' if p.get('kind')=='network' else '일일 AI Agent 분석 보고서'
  result.append({'id':r['id'],'title':title,'created':r['created'],'updated':r['updated'],'status':r['status'],'summary':p.get('summary') or p.get('error') or '', 'steps':summarize_trace(p.get('trace') or [],r['status'])})
 return {'items':result,'total':total,'offset':offset}
