from io import BytesIO
from display_utils import sanitize
from report_copy import present_report
from html import escape
from reportlab.platypus import SimpleDocTemplate,Paragraph,Table,TableStyle,Spacer,PageBreak,KeepTogether
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.pagesizes import A4
from reportlab.graphics.shapes import Drawing,Rect,String,Line
from pdf_report import fonts,stamp

def gb(v):return '미수집' if v is None else '<0.001' if 0<v<1000000 else f'{v/1e9:,.3f}'
def caption(d):return d['label']+' / '+', '.join(d.get('ips',[]) or ['IP 미확인'])
def chart(days):
 days=[d for d in days if d.get("total_bytes") is not None]
 w=493;h=140;dr=Drawing(w,h);peak=max([max(d.get('tx_bytes') or 0,d.get('rx_bytes') or 0) for d in days]+[1]);step=430/max(1,len(days))
 for i,d in enumerate(days):
  x=43+i*step;tx=d.get('tx_bytes');rx=d.get('rx_bytes')
  if tx is None:dr.add(String(x+10,45,'미수집',fontName='NCRegular',fontSize=7,textAnchor='middle',fillColor=colors.grey))
  else:
   for j,(value,color) in enumerate([(tx,'#245DEB'),(rx,'#10A58E')]):dr.add(Rect(x+j*15,25,12,(value or 0)/peak*80,fillColor=colors.HexColor(color),strokeColor=None))
  dr.add(String(x+12,12,d['day'][5:],fontName='NCRegular',fontSize=7,textAnchor='middle'))
 dr.add(Line(30,25,480,25,strokeColor=colors.HexColor('#CBD5E1')))
 dr.add(String(30,122,'최대 눈금 '+gb(peak)+' GB   |   송신(파랑) / 수신(초록)',fontName='NCRegular',fontSize=8,fillColor=colors.HexColor('#536780')))
 return dr

def connection_chart(h):
 dr=Drawing(493,150);peak=max([v['maximum'] or 0 for v in h['hourly']]+[1])
 for v in h['hourly']:
  x=15+v['hour']*19
  if v['maximum'] is None:dr.add(String(x+6,25,'-',fontName='NCRegular',fontSize=7))
  else:
   for j,(value,color) in enumerate([(v['average'],'#10A58E'),(v['maximum'],'#245DEB')]):dr.add(Rect(x+j*7,25,6,max(1,value/peak*80),fillColor=colors.HexColor(color),strokeColor=None))
   dr.add(String(x+6,110,str(v['maximum']),fontName='NCRegular',fontSize=6,textAnchor='middle'))
  dr.add(String(x+6,10,str(v['hour']),fontName='NCRegular',fontSize=7,textAnchor='middle'))
 dr.add(String(15,135,'평균: 초록 / 최대: 파랑 | 가로축: 시(KST) | 숫자: 최대 대수 | -: 미수집',fontName='NCRegular',fontSize=8))
 return dr

def build_report_v2(report):
 report=present_report(report);fonts();data=report['payload'];layout=data['server_report'];out=BytesIO();story=[];navy=colors.HexColor('#172C4C')
 styles={
  'body':ParagraphStyle('body2',fontName='NCRegular',fontSize=9,leading=14,spaceAfter=6,wordWrap='CJK',textColor=navy),
  'small':ParagraphStyle('small2',fontName='NCRegular',fontSize=7.5,leading=11,wordWrap='CJK',textColor=navy),
  'head':ParagraphStyle('head2',fontName='NCBold',fontSize=13,leading=19,spaceAfter=8,spaceBefore=12,keepWithNext=True,textColor=navy),
  'title':ParagraphStyle('title2',fontName='NCBold',fontSize=21,leading=28,spaceAfter=10,textColor=navy),
  'th':ParagraphStyle('th2',fontName='NCBold',fontSize=7.5,leading=11,wordWrap='CJK',textColor=colors.white)}
 def p(x,style='body'):return Paragraph(escape(str(x if x is not None else '미수집')).replace('\n','<br/>'),styles[style])
 def head(x):story.append(p(x,'head'))
 def table(rows,widths):
  t=Table([[p(v,'th' if i==0 else 'small') for v in r] for i,r in enumerate(rows)],colWidths=[x*mm for x in widths],repeatRows=1)
  t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),navy),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),5),('RIGHTPADDING',(0,0),(-1,-1),5),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),('LINEBELOW',(0,0),(-1,-1),.35,colors.HexColor('#DCE4EF'))]));story.extend([t,Spacer(1,8)])
 story.append(p('NetChecker','small'));story.append(p('네트워크 환경 조사 보고서','title'))
 story.append(p(layout['day']+' | 한국 시간 | 분석 '+{'done':'완료','failed':'실패'}.get(report['status'],'진행 중'),'small'))
 counts=layout['counts'];story.append(p(f"등록 {counts['registered']}대 / 수집 {counts['collected']}대 / 서버 {counts['servers']}대 / PC {counts['pcs']}대",'small'))
 story.append(p('보고서 ID: '+report['id'],'small'))
 story.append(p(data.get('data_period',''),'small'))
 ext=data.get('external_context')
 if ext:
  head('사업장 운영 참고 정보')
  holiday=ext.get('holiday',{});weather=ext.get('weather',{})
  day=ext.get('date') or layout['day']
  try: date_label=f"{int(day[5:7])}월 {int(day[8:10])}일"
  except (ValueError,TypeError): date_label='해당 날짜'
  holiday_text=(date_label+'은 공휴일입니다.'+(' ('+' · '.join(holiday.get('names',[]))+')' if holiday.get('names') else '') if holiday.get('is_public_holiday') else date_label+'은 공휴일이 아닙니다.') if holiday.get('status')=='ok' else date_label+'의 공휴일 여부를 확인하지 못했습니다.'
  story.append(p('공휴일 여부'));story.append(p(holiday_text+' 실제 근무 여부는 사업장 일정에 따라 확인해 주세요.'))
  regions=ext.get('regions',[]);parts=[]
  gyeongnam=[x for x in ['창원','함안','밀양'] if x in regions]
  if gyeongnam: parts.append('경남 '+'·'.join(gyeongnam))
  if '의왕' in regions: parts.append('경기 의왕')
  parts.extend(x for x in regions if x not in ['창원','함안','밀양','의왕'])
  story.append(p('기상특보 조회 지역'));story.append(p(', '.join(parts) or '조회 지역이 기록되지 않았습니다.'))
  count=len(weather.get('announcements',[]))
  message=('조회한 발표 자료에서 해당 지역의 기상특보 관련 발표 '+str(count)+'건을 확인했습니다.' if count else '조회한 발표 자료에서 해당 지역의 기상특보 관련 내용을 찾지 못했습니다.') if weather.get('status')=='ok' else '기상특보 자료 조회를 완료하지 못했습니다. 해당 지역의 특보 여부를 확인할 수 없습니다.'
  if weather.get('partial'): message+=' 다만, 자료가 일부만 확인되어 '+('전체 특보 현황과 다를 수 있습니다.' if count else '특보가 없다고 단정할 수는 없습니다.')
  story.append(p('기상특보 조회 결과'));story.append(p(message))
  for item in weather.get('announcements',[]):story.append(p(', '.join(item['regions'])+' / '+item['announced_at']+' / '+item['title'],'small'))
  story.append(p('분석 시 참고사항'));story.append(p('휴무나 기상 상황은 장비 사용량과 통신량에 영향을 줄 수 있습니다. 이상 징후가 확인되면 근무·백업 일정과 현장의 정전·회선 장애 여부를 함께 확인해 주세요.'))
  story.append(p('조회 범위 안내: 해당 날짜의 발표 자료에서 지역명을 기준으로 조회했습니다. 이전에 발효된 특보의 유지·해제 여부는 포함되지 않을 수 있습니다.','small'))
 crew=data.get('daily_crew')
 if crew:
  head('일일 보고서 · 분석 → 검증 → 우선 점검 목록')
  if crew.get('status')!='completed':
   story.append(p('수집된 자료가 없어 분석·검증을 진행하지 않았습니다.' if crew.get('status')=='skipped' else 'CrewAI 검증을 완료하지 못했습니다. 아래 내용은 검증 전 분석이며 우선 점검 목록은 확정하지 않았습니다.'))
  else:
   story.append(p('CrewAI 분석·검증 완료 · 관측 근거를 기준으로 확인할 순서를 정리했습니다.'))
   devices={d['id']:d for d in layout['servers']+layout['pcs']}
   checks=data.get('priority_checks',[])
   if not checks:story.append(p('검토한 후보 중 우선 점검 목록에 포함할 항목이 없습니다. 미수집 구간까지 정상임을 의미하지는 않습니다.'))
   for item in checks:
    d=devices.get(item['device']);label=caption(d) if d else item['device']
    story.append(p(str(item['rank'])+'. '+label+' · '+{'high':'우선 확인','medium':'확인 필요','low':'참고'}[item['priority']]))
    story.append(p('검증 결과: '+('추가 확인이 필요합니다.' if item['verification']=='needs_check' else '관측 근거를 확인했습니다.')))
    story.append(p(item['observation']));story.append(p('판단 근거: '+item['reason']));story.append(p('권장 조치: '+item['next_action']))
   if crew.get('excluded_count'):story.append(p('근거 대조 후 점검 대상에서 제외한 후보: '+str(crew['excluded_count'])+'건','small'))
 head('1. 서버별 일별 통신량')
 if not layout['servers']:story.append(p('서버로 지정된 장비가 없습니다. 장비 역할을 확인하세요.'))
 for server in layout['servers']:
  story.append(KeepTogether([p(caption(server),'head'),chart(server['daily'])]))
  h=server.get('connection_history')
  if h:
   story.append(KeepTogether([p('시간대별 접속 장비 수','head'),p('일일 관측 평균 '+str(h['average'] if h['average'] is not None else '미수집')+'대 / 최대 '+str(h['maximum'] if h['maximum'] is not None else '미수집')+'대 / 유효 관측 '+str(h['observed_minutes'])+'분'+(' / 부분 수집' if h['partial'] else ''),'small'),connection_chart(h)]))
   story.append(p(h['note'],'small'))

 story.append(p('최근 7일 NIC 전체 통신량(GB)입니다. 미수집 날짜는 그래프에서 제외합니다. 서버 간 통신은 각 장비에 관측되며 인터넷 회선 사용량만을 의미하지 않습니다.','small'))
 head('2. 서버별 통신 장비 TOP 20 및 포트 접속')
 for server in layout['servers']:
  head(caption(server))
  story.append(p('상대별 계측: '+{'observed':'관측됨','partial':'부분 관측 - 절단 또는 유실 확인 필요','not_collected':'미수집 - 수집기 설치·실행 상태 확인'}[server['flow_status']],'small'))
  if server['top20']:
   rows=[['순위','상대 장비 / IP','서버로 송신 GB','서버에서 수신 GB','합계 GB','비중 %']]
   for r in server['top20']:rows.append([r['rank'],r['label']+'\n'+r['ip'],gb(r['to_server_bytes']),gb(r['from_server_bytes']),gb(r['total_bytes']),r['share_percent']])
   table(rows,[10,62,26,26,27,23])
  else:story.append(p('상대별 통신량 관측 자료가 없습니다.' if not server['flow_windows'] else '계측 구간에서 관측된 상대 통신이 없습니다.'))
  story.append(p(server['flow_note'],'small'))
  head('포트 정책 외 접근 및 차단 기록')
  policy=server['policy'];story.append(p('허용 포트: '+('TCP '+','.join(map(str,policy['tcp']))+' / UDP '+','.join(map(str,policy['udp'])) if policy['configured'] else '미설정 - 정책 확인 필요'),'small'))
  if server['port_events']:
   rows=[['출발지 장비 / IP','대상 IP / 포트','구분 / 기록 수','처음 / 마지막 시각 (KST)']]
   for r in server['port_events']:rows.append([r['label']+'\n'+r['ip'],r['server_ip']+'\n'+r['protocol']+' '+str(r['port']),r['reason']+'\n'+str(r['count'])+'건',stamp(r['first_seen'])+'\n'+stamp(r['last_seen'])])
   table(rows,[49,40,35,50])
   if server['port_rows_total']>len(server['port_events']):story.append(p('목록은 기록 수 상위 '+str(len(server['port_events']))+'개 그룹입니다. 전체 그룹 '+str(server['port_rows_total'])+'개.','small'))
  else:story.append(p('조건에 해당하는 관측 기록이 없습니다. 로그 수집·감사 정책이 미확인된 경우 무접속 또는 정상 판정이 아닙니다.'))
  story.append(p(('일부 감사 기록만 수집되었습니다. ' if server.get('port_partial') else '')+server['port_note'],'small'))
 story.append(PageBreak());head('3. 성능점검대상')
 measured=[d for d in layout['pcs'] if d.get('resource_pressure')]
 if measured:
  story.append(p(measured[0]['resource_pressure']['note'],'small'))
  targets=[d for d in measured if d['resource_pressure']['review_needed']]
  if targets:
   pressure_rows=[['장비 / IP','관측 분수','CPU 70% 이상','RAM 70% 이상','동시 발생']]
   for d in targets:
    r=d['resource_pressure'];pressure_rows.append([caption(d),str(r['valid_minutes'])+'개 분',str(r['cpu_high_minutes'])+'개 분 / '+str(r['cpu_high_percent'])+'%',str(r['ram_high_minutes'])+'개 분 / '+str(r['ram_high_percent'])+'%',str(r['both_high_minutes'])+'개 분'])
   table(pressure_rows,[58,24,34,34,24])
  else:story.append(p('관측 자료에서 빈도 기준을 충족한 PC가 없습니다. 관측 부족 장비는 판단을 보류합니다.'))
 else:story.append(p('성능 점검에 필요한 관측 자료가 없습니다.'))
 head('4. 전체 PC 자원·통신량 순위')
 story.append(p('총 통신량 내림차순. CPU·RAM은 표본 최대/평균, 괄호는 최대값 또는 통신량의 항목별 순위입니다. 미수집은 순위에서 제외합니다. 단위 GB = 10억 바이트.','small'))
 rows=[['순위','장비 이름 / IP','CPU 최대/평균 % (순위)','RAM 최대/평균 % (순위)','수신 GB (순위)','송신 GB (순위)','수집 시간']]
 def metric(d,key):return '미수집' if d[key+'_max'] is None else f"{d[key+'_max']}/{d[key+'_avg']} ({d[key+'_max_rank']})"
 for d in layout['pcs']:rows.append([d['rank'] or '-',caption(d),metric(d,'cpu'),metric(d,'ram'),gb(d['rx_bytes'])+(' ('+str(d['rx_bytes_rank'])+')' if d['rx_bytes_rank'] else ''),gb(d['tx_bytes'])+(' ('+str(d['tx_bytes_rank'])+')' if d['tx_bytes_rank'] else ''),str(round(d['covered_seconds']/60))+'분'])
 if len(rows)>1:table(rows,[9,45,26,26,25,25,18])
 else:story.append(p('PC로 등록된 장비가 없습니다.'))
 security=data.get('defender_daily')
 if security:
  head('AI 디펜더 일일 보안 점검');story.append(p(security['note'],'small'))
  if security.get('review'):story.append(p(security['review']))
  if security['status']=='failed':story.append(p('AI 보안 해석 미완료입니다. 관측 자료를 직접 확인하세요.'))
  for device in security['devices']:
   head(device['label']);story.append(p(str(device['samples'])+'회 수신 / '+str(device['observed_hours'])+'개 시간대 · '+device['note']))
   story.append(p('로그인 실패 '+str(device['events']['4625'])+'건 / 백신 위협 감지 '+str(device['events']['1116'])+'건 / 보안 로그 삭제 '+str(device['events']['1102'])+'건'))
   story.append(p('백신 실시간 보호: '+('미확인' if device['realtime'] is None else '사용 중' if device['realtime'] else '확인 필요')+' / 방화벽: '+('미확인' if device['firewall'] is None else '사용 중' if device['firewall'] else '확인 필요')))
   story.append(p('적용 가능 보안·중요 업데이트: '+('미확인' if device['updates'] is None else str(device['updates'])+'건')+' / 당일 생성 승인 조치: '+str(len(device['actions']))+'건'))
 head('5. Agent 주요 작업')
 rows=[['시각 (KST)','주요 작업','결과']]
 for t in data.get('trace_summary',[]):rows.append([stamp(t.get('time')),t.get('action','')+'\n'+t.get('tool',''),t.get('detail','')])
 if len(rows)>1:table(rows,[36,49,89])
 else:story.append(p('실행 기록 없음'))
 def footer(c,doc):
  c.setFont('NCRegular',8);c.setFillColor(colors.HexColor('#64748B'));c.drawString(18*mm,11*mm,'NetChecker | 담당자 검토용');c.drawRightString(192*mm,11*mm,str(doc.page)+'페이지')
 SimpleDocTemplate(out,pagesize=A4,leftMargin=18*mm,rightMargin=18*mm,topMargin=17*mm,bottomMargin=22*mm,title='NetChecker '+layout['day']+' 네트워크 환경 조사 보고서',author='NetChecker').build(story,onFirstPage=footer,onLaterPages=footer)
 return out.getvalue()
