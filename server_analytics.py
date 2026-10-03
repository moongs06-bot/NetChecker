"""Server-centric aggregations. Peer byte rankings use ONLY server-side ETW observations."""
import json,ipaddress
from collections import defaultdict
from datetime import datetime,timedelta,timezone
from zoneinfo import ZoneInfo
from telemetry_models import ip
KST=ZoneInfo('Asia/Seoul');ROLES={'ad','erp','plm','other'}

def plm_ips(c):
 result=set()
 for row in c.execute("SELECT q.ips FROM devices d JOIN enrollment_requests q ON q.device_id=d.id WHERE d.active=1 AND d.role='plm'"):
  for addr in json.loads(row['ips'] or '[]'):
   try:result.add(ip(addr))
   except ValueError:pass
 return result


def resource_summary(rows):
 tx=rx=0;seconds=0;cpu=[];ram=[];last=None;intervals=0
 for row in rows:
  p=json.loads(row['payload']);last=row['ts']
  if p['counter_valid'] and p['interval_seconds']>0:tx+=p['tx_bytes'];rx+=p['rx_bytes'];seconds+=p['interval_seconds'];intervals+=1
  if p['resource_collection_ok']:cpu.append(p['cpu_percent']);ram.append(p['memory_percent'])
 return {'tx_bytes':tx if intervals else None,'rx_bytes':rx if intervals else None,'total_bytes':tx+rx if intervals else None,'covered_seconds':round(seconds),'cpu_avg':round(sum(cpu)/len(cpu),1) if cpu else None,'cpu_max':max(cpu) if cpu else None,'ram_avg':round(sum(ram)/len(ram),1) if ram else None,'ram_max':max(ram) if ram else None,'samples':len(rows),'last_seen':last}

def resource_pressure(rows):
 samples={}
 for row in rows:
  q=json.loads(row['payload'])
  if q.get('resource_collection_ok') and q.get('cpu_percent') is not None and q.get('memory_percent') is not None:
   samples[datetime.fromisoformat(row['ts']).replace(second=0,microsecond=0).isoformat()]=q
 n=len(samples);cpu=sum(q['cpu_percent']>=70 for q in samples.values());ram=sum(q['memory_percent']>=70 for q in samples.values());both=sum(q['cpu_percent']>=70 and q['memory_percent']>=70 for q in samples.values())
 selected=n>=30 and (cpu>=10 and cpu/n>=.2 or ram>=10 and ram/n>=.2)
 return {'valid_minutes':n,'cpu_high_minutes':cpu,'ram_high_minutes':ram,'both_high_minutes':both,'cpu_high_percent':round(cpu/n*100,1) if n else None,'ram_high_percent':round(ram/n*100,1) if n else None,'review_needed':selected,'note':'유효 관측 30개 분 이상 중 CPU 또는 RAM 70% 이상이 10개 분 이상·20% 이상이면 점검 대상으로 분류합니다. 비율은 수집된 표본 기준이며 하루 전체 지속 시간을 뜻하지 않습니다. 작업량 대비 성능 부족 가능성이 있으나 프로세스·실제 응답 속도·하드웨어 사양 확인 후 판단합니다.'}

def connection_history(rows,excluded):
 minutes={}
 for row in rows:
  q=json.loads(row['payload'])
  if not q.get('connection_collection_ok'):continue
  peers=set()
  for item in q.get('connections',[]):
   try:addr=ip(item['remote_ip']);parsed=ipaddress.ip_address(addr)
   except (ValueError,KeyError):continue
   if addr in excluded or parsed.version!=4 or parsed.is_loopback or parsed.is_unspecified or addr.startswith('169.') or item.get('state','').lower()!='established':continue
   peers.add(addr)
  t=datetime.fromisoformat(row['ts']).astimezone(KST).replace(second=0,microsecond=0)
  minutes[t]=(len(peers),q.get('connections_total',0)>len(q.get('connections',[])))
 hourly=[]
 for hour in range(24):
  values=[v for t,v in minutes.items() if t.hour==hour]
  hourly.append({'hour':hour,'average':round(sum(v[0] for v in values)/len(values),1) if values else None,'maximum':max(v[0] for v in values) if values else None,'observed_minutes':len(values),'partial':any(v[1] for v in values)})
 return {'average':round(sum(v[0] for v in minutes.values())/len(minutes),1) if minutes else None,'maximum':max(v[0] for v in minutes.values()) if minutes else None,'observed_minutes':len(minutes),'partial':any(v[1] for v in minutes.values()),'hourly':hourly,'note':'한국 시간 기준, 매분 중복 IP를 제외한 관측 연결 장비 수입니다. 평균은 유효 관측 분 기준이며 미수집은 0으로 계산하지 않습니다. 부분 수집 시 실제보다 적을 수 있으며 서버가 먼저 연결한 상대도 포함될 수 있습니다. 로그인 사용자 수가 아닙니다.'}

def build(c,day,start,end,search="",rolling=False,include_clients=False):
 devices=[dict(r) for r in c.execute('SELECT d.id,d.label,d.role,q.ips FROM devices d LEFT JOIN enrollment_requests q ON q.device_id=d.id WHERE d.active=1')]
 by_ip=defaultdict(list)
 for d in devices:
  d['ips']=[ip(x) for x in json.loads(d['ips'] or '[]')];d['ip']=d['ips'][0] if d['ips'] else '미확인'
  for addr in d['ips']:by_ip[addr].append(d)
 def peer(addr):
  matches=by_ip.get(addr,[])
  return {'ip':addr,'device':matches[0]['id'] if len(matches)==1 else None,'label':matches[0]['label'] if len(matches)==1 else 'IP 중복 - 식별 보류' if matches else '미등록 상대'}
 day_start=datetime.strptime(day,'%Y-%m-%d').replace(tzinfo=KST);week=(day_start-timedelta(days=6)).astimezone(timezone.utc)
 servers=[];pcs=[];internal_plm=plm_ips(c)
 for d in devices:
  rows=c.execute('SELECT ts,payload FROM samples WHERE device=? AND ts>=? AND ts<? ORDER BY ts',(d['id'],start.isoformat(),end.isoformat())).fetchall()
  stats=resource_summary(rows)
  if rolling:
   from network_analysis import metrics
   stats.update(metrics(rows,start,end))
  excluded=internal_plm if d['role']=='plm' else set()
  entry={**d,**stats}
  if excluded:entry['exclusion_note']='등록된 PLM 서버 간 및 자체 통신은 접속 목록·순위·포트 조사에서 제외합니다. 서버 전체 통신량에는 포함됩니다.'
  if d['role'] not in ROLES:
   entry['resource_pressure']=resource_pressure(rows)
   pcs.append(entry);continue
  entry['connection_history']=connection_history(rows,excluded)
  daily={}
  history=[] if rolling else c.execute('SELECT ts,payload FROM samples WHERE device=? AND ts>=? AND ts<? ORDER BY ts',(d['id'],week.isoformat(),(day_start+timedelta(days=1)).astimezone(timezone.utc).isoformat())).fetchall()
  for r in history:daily.setdefault(datetime.fromisoformat(r['ts']).astimezone(KST).date().isoformat(),[]).append(r)
  entry['daily']=[{'day':(day_start-timedelta(days=6-i)).date().isoformat(),**resource_summary(daily.get((day_start-timedelta(days=6-i)).date().isoformat(),[]))} for i in range(7)]
  policy_row=c.execute('SELECT payload FROM server_policies WHERE device=?',(d['id'],)).fetchone();policy=json.loads(policy_row['payload']) if policy_row else {'configured':False,'tcp':[],'udp':[]}
  if rolling:entry['daily']=[]
  server_match=not search or any(search in addr for addr in d['ips'])
  # A separate latest TCP snapshot, never filtered by the allowed-port policy.
  latest=c.execute('SELECT ts,payload FROM samples WHERE device=? ORDER BY ts DESC LIMIT 1',(d['id'],)).fetchone() if include_clients else None
  q=json.loads(latest['payload']) if latest else {};observed=latest['ts'] if latest else None
  fresh=bool(latest and 0<=(datetime.now(timezone.utc)-datetime.fromisoformat(observed)).total_seconds()<=180)
  clients={};all_clients=set()
  if fresh and q.get('connection_collection_ok'):
   for connection in q.get('connections',[]):
    addr=connection['remote_ip']
    if addr in excluded:continue
    try:parsed=ipaddress.ip_address(addr)
    except ValueError:continue
    if parsed.version!=4 or parsed.is_loopback or parsed.is_unspecified or addr.startswith('169.') or connection.get('state','').lower()!='established':continue
    all_clients.add(addr)
    if not server_match and search not in addr:continue
    if addr not in clients:clients[addr]={**peer(addr),'connections':0,'ports':[],'server_ports':[]}
    clients[addr]['connections']+=1
    local_port=connection.get('local_port')
    if local_port is not None and local_port not in clients[addr]['server_ports']:clients[addr]['server_ports'].append(local_port)
    port=connection.get('remote_port')
    if port is not None and port not in clients[addr]['ports']:clients[addr]['ports'].append(port)
  for client in clients.values():client['ports'].sort();client['server_ports'].sort()
  entry['connected_client_count']=len(all_clients) if fresh and q.get('connection_collection_ok') else None
  entry['connected_clients']=sorted(clients.values(),key=lambda x:(-x['connections'],x['ip']))
  entry['connections_observed_at']=observed
  entry['connections_state']='observed' if fresh and q.get('connection_collection_ok') else 'stale' if latest and not fresh else 'unavailable'
  entry['connections_partial']=q.get('connections_total',0)>len(q.get('connections',[]))
  entry['policy']=policy;peers=defaultdict(lambda:{'to_server_bytes':0,'from_server_bytes':0});windows=[]
  # Use whole windows ending in the requested interval. Never add client-side observations again.
  for r in c.execute('SELECT payload FROM flow_windows WHERE device=? AND ended_at>? AND ended_at<=?',(d['id'],start.isoformat(),end.isoformat())):
   p=json.loads(r['payload']);windows.append(p)
   for f in p['flows']:
    if f['remote_ip'] in excluded:continue
    v=peers[f['remote_ip']];v['to_server_bytes']+=f['rx_bytes'];v['from_server_bytes']+=f['tx_bytes']
  ranking=[{**peer(addr),**v,'total_bytes':v['to_server_bytes']+v['from_server_bytes']} for addr,v in peers.items()];ranking.sort(key=lambda x:(-x['total_bytes'],x['ip']))
  total=sum(r['total_bytes'] for r in ranking)
  for i,r in enumerate(ranking):r['rank']=i+1;r['share_percent']=round(r['total_bytes']/total*100,2) if total else 0
  matched=ranking if server_match else [r for r in ranking if search in r['ip']]
  entry['top20']=matched[:20];entry['peer_count']=len(ranking);entry['flow_windows']=len(windows);entry['flow_total_bytes']=total if windows else None
  entry['flow_status']='partial' if any(w['truncated'] or w['lost_events']!=0 for w in windows) else 'observed' if windows else 'not_collected'
  entry['flow_note']='서버에서 관측한 TCP/UDP 바이트 기준. NIC 전체 바이트와 다를 수 있음. 유실·절단이 있으면 순위도 부분 관측.'
  grouped={}
  for r in c.execute('SELECT payload FROM port_events WHERE device=? AND ts>=? AND ts<?',(d['id'],start.isoformat(),end.isoformat())):
   e=json.loads(r['payload'])
   if e['source_ip'] in excluded:continue
   # Inbound server destination only: never classify client ephemeral ports as server service ports.
   if e['destination_ip'] not in d['ips']:continue
   configured=policy['configured'];allowed=e['destination_port'] in policy[e['protocol'].lower()]
   if configured and allowed and e['action']!='blocked':continue
   reason='차단 기록' if e['action']=='blocked' else '허용 포트 정책 외 접근' if configured else '정책 확인 필요'
   key=(e['source_ip'],e['destination_ip'],e['destination_port'],e['protocol'],e['action'],reason)
   if key not in grouped:grouped[key]={**peer(e['source_ip']),'server_ip':e['destination_ip'],'port':e['destination_port'],'protocol':e['protocol'],'action':e['action'],'reason':reason,'count':0,'first_seen':e['time'],'last_seen':e['time']}
   g=grouped[key];g['count']+=1;g['first_seen']=min(g['first_seen'],e['time']);g['last_seen']=max(g['last_seen'],e['time'])
  all_ports=sorted(grouped.values(),key=lambda x:(-x['count'],x['ip']))
  if not server_match:all_ports=[r for r in all_ports if search in r['ip']]
  if not server_match and not matched and not all_ports and not clients:continue
  entry['port_events']=all_ports[:100];entry['port_rows_total']=len(all_ports)
  statuses=[json.loads(r['payload']).get('port_status','not_collected') for r in rows]
  entry['port_partial']='truncated' in statuses
  entry['port_status']='events_observed' if all_ports else 'readable_policy_unverified' if 'readable_policy_unverified' in statuses else 'not_collected'
  entry['port_note']='Windows 5156 허용·5157 차단 기록 기준. 허용은 연결 완료를 뜻하지 않음. 감사 정책·누락 여부 미확인 시 무기록을 무접속으로 판단하지 않음.'
  servers.append(entry)
 pcs.sort(key=lambda d:(d['total_bytes'] is None,-(d['total_bytes'] or 0),d['id']))
 for metric in ('cpu_max','ram_max','rx_bytes','tx_bytes'):
  values=sorted({d[metric] for d in pcs if d[metric] is not None},reverse=True)
  ranks={v:i+1 for i,v in enumerate(values)}
  for d in pcs:d[metric+'_rank']=ranks.get(d[metric])
 rank=0
 for d in pcs:
  if d['total_bytes'] is not None:rank+=1;d['rank']=rank
  else:d['rank']=None
 return {'version':2,'day':day,'timezone':'Asia/Seoul','window_start':start.isoformat(),'window_end':end.isoformat(),'servers':servers,'pcs':pcs,'counts':{'registered':len(devices),'servers':len(servers),'pcs':len(pcs),'collected':sum(d['samples']>0 for d in servers+pcs)}}

def safe(value,alias):
 if isinstance(value,list):return [safe(v,alias) for v in value]
 if not isinstance(value,dict):return value
 result={}
 for key,v in value.items():
  if key in ('label','hostname'):continue
  if key in ('ip','server_ip','source_ip','destination_ip'):result[key]=alias('ip',v) if v!='미확인' else 'unknown'
  elif key=='ips':result[key]=[alias('ip',x) for x in v]
  else:result[key]=safe(v,alias)
 return result
