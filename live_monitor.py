"""Read-only live fleet view. No LLM calls, payload contents, or control actions."""
import ipaddress
import json, sqlite3, threading, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from display_utils import visible_ipv4
from network_analysis import metrics
from server_analytics import ROLES,plm_ips

FIELDS=('counter_valid','interval_seconds','tx_bytes','rx_bytes','resource_collection_ok','cpu_percent','memory_percent','disk_percent')
PROJECT='json_object('+','.join("'"+k+"',json_extract(payload,'$."+k+"')" for k in FIELDS)+')'
POLICY={'sample_seconds':60,'refresh_seconds':15,'stale_seconds':180,'recent_minutes':5,'baseline_hours':6,'baseline_refresh_seconds':300,'coverage_percent':80,'caution_ratio':150,'warning_ratio':300,'resource_caution':90,'resource_warning':95,'resource_samples':3}

def rows_for(c,ident,start,end):
    return c.execute('SELECT ts,'+PROJECT+' AS payload FROM samples WHERE device=? AND ts>? AND ts<=? ORDER BY ts,batch',(ident,start.isoformat(),end.isoformat())).fetchall()

def assess(recent,baseline,current,rows,available):
    alerts=[];ratio=None
    if not available:return alerts,ratio,'수집 지연'
    enough=recent['coverage_percent']>=80 and baseline['coverage_percent']>=80 and (baseline['bytes_per_minute'] or 0)>0
    if enough:
        ratio=recent['bytes_per_minute']/baseline['bytes_per_minute']*100
        if round(ratio,9)>=150:
            alerts.append({'level':'warning' if round(ratio,9)>=300 else 'caution','reason':f"최근 5분 통신량이 이전 6시간 평균의 {ratio/100:.1f}배입니다."})
    tail=rows[-3:]
    contiguous=len(tail)==3 and all(0<(datetime.fromisoformat(tail[i]['ts'])-datetime.fromisoformat(tail[i-1]['ts'])).total_seconds()<=90 for i in (1,2))
    if contiguous:
        values=[json.loads(r['payload']) for r in tail]
        if all(p.get('resource_collection_ok') for p in values):
            for field,label in [('cpu_percent','CPU'),('memory_percent','메모리')]:
                floor=min(p[field] for p in values)
                if floor>=90:alerts.append({'level':'warning' if floor>=95 else 'caution','reason':f'{label} 사용률이 최근 3회 연속 {95 if floor>=95 else 90}% 이상입니다.'})
    return alerts,ratio,'비교 완료' if enough else '비교 대기'

def build(c,end,baseline_cache=None):
    cache=baseline_cache if baseline_cache is not None else {}
    start=end-timedelta(minutes=5);devices=[]
    registered=c.execute('SELECT d.id,d.label,d.role,q.ips FROM devices d LEFT JOIN enrollment_requests q ON q.device_id=d.id WHERE d.active=1 ORDER BY d.label,d.id').fetchall()
    for d in registered:
        rows=rows_for(c,d['id'],end-timedelta(minutes=30 if d['role'] in ROLES else 5),end)
        last=rows[-1] if rows else c.execute('SELECT ts,'+PROJECT+' AS payload FROM samples WHERE device=? AND ts<=? ORDER BY ts DESC LIMIT 1',(d['id'],end.isoformat())).fetchone()
        p=json.loads(last['payload']) if last else {}
        age=(end-datetime.fromisoformat(last['ts'])).total_seconds() if last else None
        fresh=age is not None and 0<=age<=180
        interval=p.get('interval_seconds') or 0
        valid=fresh and bool(p.get('counter_valid')) and 0<interval<=180
        baseline=cache.get(d['id'])
        if baseline is None or not 0<=(end-datetime.fromisoformat(baseline['at'])).total_seconds()<300:
            bstart=start-timedelta(hours=6)
            baseline={'at':end.isoformat(),'start':bstart.isoformat(),'end':start.isoformat(),'metrics':metrics(rows_for(c,d['id'],bstart,start),bstart,start)}
            cache[d['id']]=baseline
        recent=metrics(rows,start,end)
        alerts,ratio,comparison=assess(recent,baseline['metrics'],p,rows,fresh)
        # Never infer a live traffic alert from stale or invalid counters.
        if not valid:
            alerts=[a for a in alerts if not a['reason'].startswith('최근 5분')];ratio=None;comparison='통신 계측 대기' if fresh else '수집 지연' if last else '수집 대기'
        rate=lambda key:p[key]/interval if valid else None
        tx,rx=rate('tx_bytes'),rate('rx_bytes')
        severity='warning' if any(a['level']=='warning' for a in alerts) else 'caution' if alerts else 'none'
        timeline=[]
        for r in rows if d['role'] in ROLES else []:
            q=json.loads(r['payload']);seconds=q.get('interval_seconds') or 0
            timeline.append({'time':r['ts'],'mbps':(q['tx_bytes']+q['rx_bytes'])/seconds*8/1e6 if q.get('counter_valid') and 0<seconds<=180 else None})
        devices.append({'id':d['id'],'label':d['label'],'role':d['role'],'ips':visible_ipv4(json.loads(d['ips'] or '[]')),'last_seen':last['ts'] if last else None,'age_seconds':age,'state':'live' if valid else 'waiting' if fresh else 'stale' if last else 'missing','tx_bps':tx,'rx_bps':rx,'total_bps':tx+rx if valid else None,'interval_seconds':interval if valid else None,'tx_bytes':p.get('tx_bytes') if valid else None,'rx_bytes':p.get('rx_bytes') if valid else None,'cpu':p.get('cpu_percent') if fresh and p.get('resource_collection_ok') else None,'ram':p.get('memory_percent') if fresh and p.get('resource_collection_ok') else None,'alerts':alerts,'severity':severity,'comparison':comparison,'ratio_percent':ratio,'baseline_start':baseline['start'],'baseline_end':baseline['end'],'trend':timeline,'cpu_max':recent['cpu_max'],'ram_max':recent['ram_max'],'recent_coverage_percent':recent['coverage_percent']})
    internal_plm=plm_ips(c)
    for item in devices:
        if item['role'] not in ROLES:continue
        row=c.execute('SELECT ts,payload FROM samples WHERE device=? AND ts<=? ORDER BY ts DESC LIMIT 1',(item['id'],end.isoformat())).fetchone()
        q=json.loads(row['payload']) if row else {}
        fresh=bool(row and 0<=(end-datetime.fromisoformat(row['ts'])).total_seconds()<=180 and q.get('connection_collection_ok'))
        peers=set()
        if fresh:
            for connection in q.get('connections',[]):
                addr=connection.get('remote_ip','')
                if item['role']=='plm' and addr in internal_plm:continue
                try:parsed=ipaddress.ip_address(addr)
                except ValueError:continue
                if parsed.version==4 and not parsed.is_loopback and not parsed.is_unspecified and not addr.startswith('169.') and connection.get('state','').lower()=='established':peers.add(addr)
        item['connected_client_count']=len(peers) if fresh else None
        item['connections_partial']=q.get('connections_total',0)>len(q.get('connections',[]))
    servers=[d for d in devices if d['role'] in ROLES]
    pcs=sorted((d for d in devices if d['role'] not in ROLES),key=lambda d:(d['total_bps'] is None,-(d['total_bps'] or 0),d['id']))
    rank=0
    for d in pcs:
        if d['total_bps'] is not None:rank+=1;d['rank']=rank
        else:d['rank']=None
    return {'generated_at':end.isoformat(),'policy':POLICY,'servers':servers,'pcs':pcs,'counts':{'registered':len(devices),'servers':len(servers),'pcs':len(pcs),'live':sum(d['state']=='live' for d in devices),'delayed':sum(d['state']!='live' for d in devices),'warning':sum(d['severity']=='warning' for d in devices),'caution':sum(d['severity']=='caution' for d in devices)},'scope':'최근 수집 구간의 송신+수신 속도 기준입니다. 내부 통신은 양쪽 장비에 집계될 수 있으며 인터넷 회선 사용량과는 다릅니다.'}

_lock=threading.Lock();_cached={};_baselines={}
def get_snapshot(path):
    key=str(Path(path).resolve())
    with _lock:
        now=time.monotonic();previous=_cached.get(key)
        if previous and now-previous[0]<15:return previous[1]
        with sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,timeout=15) as c:
            c.row_factory=sqlite3.Row
            value=build(c,datetime.now(timezone.utc),_baselines.setdefault(key,{}))
        active={d['id'] for d in value['servers']+value['pcs']}
        _baselines[key]={k:v for k,v in _baselines[key].items() if k in active}
        _cached[key]=(time.monotonic(),value)
        return value

HOURS=(1,2,4,6,8,12,24)
def period_trend(rows,start,end):
    # Equal-width chart buckets. Missing observation time stays missing, not zero.
    width=(end-start).total_seconds()/60
    buckets=[{'bytes':0.,'seconds':0.} for _ in range(60)];cursor=start
    for row in rows:
        ts=datetime.fromisoformat(row['ts']);p=json.loads(row['payload']);interval=p.get('interval_seconds') or 0
        if not p.get('counter_valid') or not 0<interval<=180:continue
        left=max(start,ts-timedelta(seconds=interval),cursor);right=min(end,ts)
        if right<=left:continue
        cursor=right;speed=(p['tx_bytes']+p['rx_bytes'])/interval
        while left<right:
            index=min(59,int((left-start).total_seconds()/width))
            edge=min(right,start+timedelta(seconds=(index+1)*width));seconds=(edge-left).total_seconds()
            if seconds<=0:break
            buckets[index]['bytes']+=speed*seconds;buckets[index]['seconds']+=seconds;left=edge
    return [{'time':(start+timedelta(seconds=(i+.5)*width)).isoformat(),'mbps':b['bytes']/b['seconds']*8/1e6 if b['seconds'] else None,'covered_seconds':b['seconds']} for i,b in enumerate(buckets)]

def build_ranking(c,hours,end):
    if hours not in HOURS:raise ValueError('Unsupported period')
    start=end-timedelta(hours=hours);pcs=[];servers=[]
    devices=c.execute("SELECT d.id,d.label,d.role,q.ips FROM devices d LEFT JOIN enrollment_requests q ON q.device_id=d.id WHERE d.active=1 ORDER BY d.label,d.id").fetchall()
    for d in devices:
        rows=rows_for(c,d['id'],start,end);result=metrics(rows,start,end)
        item={'id':d['id'],'label':d['label'],'role':d['role'],'ips':visible_ipv4(json.loads(d['ips'] or '[]')),'tx_bytes':result['tx_bytes'],'rx_bytes':result['rx_bytes'],'total_bytes':result['total_bytes'],'cpu_avg':result['cpu_avg'],'ram_avg':result['ram_avg'],'cpu_max':result['cpu_max'],'ram_max':result['ram_max'],'covered_seconds':result['covered_seconds'],'coverage_percent':result['coverage_percent'],'last_seen':result['last_seen'],'average_mbps':result['average_mbps']}
        if d['role'] in ROLES:
            item.update(trend=period_trend(rows,start,end),trend_step_seconds=hours*60,window_start=start.isoformat(),window_end=end.isoformat());servers.append(item)
        else:pcs.append(item)
    pcs.sort(key=lambda d:(d['total_bytes'] is None,-(d['total_bytes'] or 0),d['id']))
    rank=0
    for d in pcs:
        if d['total_bytes'] is not None:rank+=1;d['rank']=rank
        else:d['rank']=None
    return {'hours':hours,'window_start':start.isoformat(),'window_end':end.isoformat(),'generated_at':end.isoformat(),'pcs':pcs,'servers':servers,'registered':len(pcs),'collected':rank,'refresh_seconds':60}

_ranking_lock=threading.Lock();_rankings={}
def get_ranking(path,hours):
    if hours not in HOURS:raise ValueError('Unsupported period')
    key=(str(Path(path).resolve()),hours)
    with _ranking_lock:
        previous=_rankings.get(key)
        if previous and time.monotonic()-previous[0]<60:return previous[1]
        with sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,timeout=15) as c:
            c.row_factory=sqlite3.Row;value=build_ranking(c,hours,datetime.now(timezone.utc))
        _rankings[key]=(time.monotonic(),value)
        return value
