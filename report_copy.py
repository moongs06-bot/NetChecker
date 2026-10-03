"""Readable report presentation; raw evidence and trace stay untouched."""
import re
from datetime import datetime, timezone, timedelta
from display_utils import sanitize

WRITING_STYLE = '''
사용자에게 보이는 summary, observation, explanation, next_action, limitations는 짧고 쉬운 한국어 존댓말(합니다/필요합니다/없습니다)로 작성하세요.
내부 필드명, null, configured=false, flow_status, ETW/NIC 약어와 UTC 환산 설명을 문장에 나열하지 마세요. 도구 입력과 evidence_ids는 원래 식별자를 유지하세요.
자료가 없으면 무엇을 확인할 수 없는지와 필요한 다음 조치만 설명하세요. 같은 한계는 한 번만 적고 최대 5개 항목으로 정리하세요.
기간은 한국 시간으로 간결히 설명하세요. 수집이 끊긴 구간을 전체 기간 관측으로 표현하지 마세요.
조사 계획은 주요 작업만 한 문장으로 작성하세요.
'''

def polite(text):
    text = str(text or '')
    for old, new in [('확인해야 한다','확인이 필요합니다'),('필요하다','필요합니다'),('수 없다','수 없습니다'),('없다','없습니다'),('아니다','아닙니다'),('않았다','않았습니다'),('않는다','않습니다'),('있다','있습니다'),('불가하다','어렵습니다'),('보류한다','보류합니다'),('확인한다','확인합니다'),('판단한다','판단합니다'),('의심된다','의심됩니다'),('확인된다','확인됩니다'),('나타났다','나타났습니다'),('관측되었다','관측되었습니다'),('것이다','것입니다')]:
        text = re.sub(re.escape(old)+r'(?=[.!?\s]|$)',new,text)
    return text

STAGES = [
 ('plan','조사 계획','확인할 항목과 조사 순서를 정했습니다.'),
 ('data','데이터 확인','장비별 수집 현황과 서버 상태를 확인했습니다.'),
 ('compare','이상 징후 비교','통신량과 자원 사용량을 비교했습니다.'),
 ('inspect','원인 확인','의심 장비의 관측 자료와 정상 작업 일정을 대조했습니다.'),
 ('report','보고서 작성','조사 근거를 검토하고 보고서를 정리했습니다.'),
 ('daily_analysis','일일 분석','수집된 근거로 일일 분석 후보를 정리했습니다.'),
 ('daily_review','일일 검증','원본 근거와 분석 결론을 대조했습니다.'),
 ('daily_priority','우선 점검 목록','검증된 결과로 우선 점검 순서를 정했습니다.')]
TOOLS = {'plan_investigation':'plan','fleet_overview':'data','network_overview':'data','inspect_server':'data','fleet_rankings':'compare','network_candidates':'compare','inspect_device':'inspect','inspect_candidates':'inspect','check_expected_activity':'inspect','submit_report':'report'}
ACTIONS = {'일일 분석':'daily_analysis','일일 검증':'daily_review','우선 점검 목록':'daily_priority','조사 계획':'plan','전체 장비 확인':'data','전용 비교 정책 확인':'data','서버 통신·정책 조사':'data','전체 PC 순위 비교':'compare','150% 이상 PC 순위 조회':'compare','장비·기준선 조사':'inspect','정상 작업 대조':'inspect','결과 검증 완료':'report','네트워크 결과 검증 완료':'report'}

def summarize_trace(trace, status=None):
    seen = {}
    for entry in trace or []:
        group = TOOLS.get(entry.get('tool')) or ACTIONS.get(entry.get('action'))
        if not group:
            continue
        state = entry.get('status') or 'completed'
        seen[group] = {'time':entry.get('time'),'status':state}
    if status == 'failed':
        seen['report'] = {'time':(trace or [{}])[-1].get('time'),'status':'failed'}
    result = []
    for key, title, detail in STAGES:
        if key not in seen:
            continue
        row = seen[key]
        state = row['status']
        text = '진행 중입니다.' if state == 'running' else '확인을 완료하지 못했습니다. 재확인이 필요합니다.' if state == 'failed' else detail
        result.append({**row,'action':title,'detail':text})
    return result

def parse(value):
    try:
        result = datetime.fromisoformat(str(value).replace('Z','+00:00'))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (ValueError, TypeError):
        return None

def period(payload):
    layout = payload.get('network_report') or payload.get('server_report') or {}
    start, end = parse(layout.get('window_start')), parse(layout.get('window_end'))
    if not start or not end:
        return ''
    if payload.get('server_report'):
        observed=[parse(d.get('last_seen')) for d in layout.get('servers',[])+layout.get('pcs',[])]
        observed=[d for d in observed if d and start<=d<=end]
        if observed:end=max(observed)
    zone = timezone(timedelta(hours=9))
    start, end = start.astimezone(zone), end.astimezone(zone)
    fmt = lambda d:f'{d.month}월 {d.day}일 {d:%H:%M}'
    return f'이 보고서는 {fmt(start)}부터 {fmt(end)}까지의 기간에 수집된 데이터를 기반으로 합니다. (한국 시간)'

def readable_limits(payload):
    result=[]
    def add(text):
        if text not in result:result.append(text)
    for value in payload.get('limitations',[]):
        text=str(value)
        if any(s in text for s in ('flow_status','flow_total_bytes','ETW','TCP/UDP 바이트 TOP20')):
            add('장비별 통신량 자료가 없는 구간은 서버 접속 장비 순위를 확인할 수 없습니다. 수집 프로그램의 실행 상태 확인이 필요합니다.')
        elif any(s in text for s in ('configured=','port_status','allowed','blocked')):
            add('허용 포트 설정이나 접속 기록이 부족해 의심스러운 포트 접근을 확인할 수 없습니다. 서버 설정과 기록 수집 상태 확인이 필요합니다.')
        elif any(s in text for s in ('분석 창','관측 시간','누적 순위','표본기간','하루 전체')):
            add('장비마다 수집된 시간이 다를 수 있어 사용량 순위만으로 과부하를 판단하기 어렵습니다.')
        elif any(s in text for s in ('baseline','기준선','결측','null')):
            add('과거 자료가 부족한 장비는 평소보다 사용량이 늘었는지 비교하기 어렵습니다. 미수집 값은 0으로 판단하지 않습니다.')
        elif any(s in text for s in ('연결 표본','절단','truncated')):
            add('일부 연결 기록이 빠져 있어 모든 접속이나 장비별 데이터 이동량을 확인할 수 없습니다.')
        elif any(s in text for s in ('L2','STP','연결 스냅샷','루프·침해 여부')):
            add('현재 자료만으로 네트워크 루프나 보안 침해를 확정할 수 없습니다. 네트워크 장비 기록과 응답 속도 확인이 필요합니다.')
        elif '빈 목록' in text and any(s in text for s in ('백업','유지보수')):
            add('등록된 백업·유지보수 일정이 없습니다. 실제 작업 여부는 담당자 확인이 필요합니다.')
        elif any(s in text for s in ('동일 IP','같은 IP','IP 충돌')):
            add('같은 IP가 여러 장비에 표시된 경우 실제 장비 정보를 확인해야 합니다. 이 정보만으로 IP 충돌을 단정할 수 없습니다.')
        else:add(polite(text))
    return result

def present_report(report):
    report=sanitize(report)
    payload=report.get('payload',{})
    payload['summary']=polite(payload.get('summary',''))
    for server in payload.get('server_report',{}).get('servers',[]):
        server['flow_note']='서버에서 직접 측정한 장비별 통신량입니다. 일부 기록이 빠진 경우 실제 사용량과 순위가 다를 수 있습니다.' if server.get('flow_status')!='not_collected' else '장비별 통신량 자료가 없어 접속 장비 순위를 확인할 수 없습니다. 수집 프로그램의 실행 상태 확인이 필요합니다.'
        server['port_note']='접속 허용 기록만으로 실제 연결 성공을 판단할 수 없습니다. 차단 기록은 서버가 접근을 막은 내역입니다. 기록이 없더라도 접속이 없었다고 단정할 수 없습니다.'
    for finding in payload.get('findings',[]):
        for key in ('observation','explanation','next_action'):
            if key in finding:finding[key]=polite(finding[key])
    payload['data_period']=period(payload)
    payload['readable_limitations']=readable_limits(payload)
    payload['trace_summary']=summarize_trace(payload.get('trace',[]),report.get('status'))
    return report
