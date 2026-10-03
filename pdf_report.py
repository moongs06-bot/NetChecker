"""Korean PDF export from a saved report; does not call the AI or change data."""
from io import BytesIO
from display_utils import sanitize
from report_copy import present_report
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from html import escape
from threading import Lock
import os
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

LOCK=Lock();KST=ZoneInfo('Asia/Seoul')
def fonts():
 with LOCK:
  if 'NCRegular' not in pdfmetrics.getRegisteredFontNames():
   folder=Path(os.getenv('NETCHECKER_FONT_DIR','/usr/share/fonts/truetype/nanum'))
   pdfmetrics.registerFont(TTFont('NCRegular',str(folder/'NanumGothic.ttf')))
   pdfmetrics.registerFont(TTFont('NCBold',str(folder/'NanumGothicBold.ttf')))
   pdfmetrics.registerFontFamily('NCRegular',normal='NCRegular',bold='NCBold',italic='NCRegular',boldItalic='NCBold')

def stamp(value):
 try:return datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(KST).strftime('%Y-%m-%d %H:%M:%S')
 except (ValueError,TypeError,AttributeError):return str(value or '기록 없음')

def build_report(report,labels=None):
 report=present_report(report)
 if report.get('payload', {}).get('server_report', {}).get('version') == 2:
  from pdf_server_report import build_report_v2
  return build_report_v2(report)
 fonts();labels=labels or {};payload=report['payload'];output=BytesIO();story=[]
 navy=colors.HexColor('#172C4C');blue=colors.HexColor('#245DEB');muted=colors.HexColor('#586B83')
 styles={
  'body':ParagraphStyle('body',fontName='NCRegular',fontSize=9.5,leading=15,wordWrap='CJK',spaceAfter=7,textColor=navy),
  'small':ParagraphStyle('small',fontName='NCRegular',fontSize=8,leading=12,wordWrap='CJK',textColor=muted),
  'heading':ParagraphStyle('heading',fontName='NCBold',fontSize=13,leading=19,spaceBefore=13,spaceAfter=9,textColor=navy,keepWithNext=True),
  'title':ParagraphStyle('title',fontName='NCBold',fontSize=23,leading=30,spaceAfter=12,textColor=navy),
  'th':ParagraphStyle('th',fontName='NCBold',fontSize=8.5,leading=13,textColor=colors.white,wordWrap='CJK'),
 }
 def p(text,style='body'):return Paragraph(escape(str(text if text is not None else '확인되지 않음')).replace('\n','<br/>'),styles[style])
 def heading(text):story.append(p(text,'heading'))
 def table(rows,widths,header=True,compact=False):
  cells=[[p(v,'th' if header and i==0 else 'small') for v in row] for i,row in enumerate(rows)]
  t=Table(cells,colWidths=widths,repeatRows=1 if header else 0,hAlign='LEFT')
  cmds=[('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),5 if compact else 7),('BOTTOMPADDING',(0,0),(-1,-1),5 if compact else 7),('LINEBELOW',(0,0),(-1,-1),.4,colors.HexColor('#DDE4EE'))]
  if header:cmds+=[('BACKGROUND',(0,0),(-1,0),navy)]
  t.setStyle(TableStyle(cmds));story.append(t);story.append(Spacer(1,9))
 kind='네트워크 지연·루프 의심 분석' if payload.get('kind')=='network' else '일일 보안 분석'
 status={'done':'완료','failed':'실패','running':'진행 중'}.get(report.get('status'),'확인 필요')
 story.extend([p('NetChecker','small'),p('네트워크 환경 조사 보고서','title'),p(kind,'heading')])
 table([['분석 대상일','분석 상태','분석 요청 시각 (한국 시간)'],[report.get('day',''),status,stamp(report.get('created'))]],[42*mm,30*mm,102*mm])
 story.append(p('보고서 ID: '+report.get('id',''),'small'))
 if payload.get('minutes'):story.append(p('조사 범위: 실행 시점 기준 최근 '+str(payload['minutes'])+'분','small'))
 mode=payload.get('mode')
 story.append(p('분석 방식: '+('등록된 AI Agent의 도구 조사 결과' if mode=='registered_agent' else '수집 자료 없음' if mode=='no_data' else '분석 미완료'),'small'))
 story.append(p(payload.get('data_period',''),'small'))
 heading('1. 조사 요약');story.append(p(payload.get('summary','요약 없음')))
 findings=payload.get('findings',[])
 heading('2. 확인할 사항 및 다음 조치')
 if not findings:story.append(p('기록된 조사 항목이 없습니다. 자료 부족이나 분석 실패인 경우 정상 상태를 의미하지 않습니다.'))
 priorities={'high':'우선 확인','medium':'확인 필요','low':'참고'}
 for index,f in enumerate(findings,1):
  heading(str(index)+'. '+labels.get(f.get('device'),f.get('device','장비 미지정'))+' | '+priorities.get(f.get('priority'),'확인 필요'))
  story.append(p('관측: '+str(f.get('observation',''))));story.append(p('해석: '+str(f.get('explanation',''))));story.append(p('다음 조치: '+str(f.get('next_action',''))))
  story.append(p('근거: '+', '.join(f.get('evidence_ids',[])),'small'))
 heading('3. 확인 범위와 한계')
 for value in payload.get('readable_limitations',[]) or ['이 보고서는 관측 자료에 기반한 조사 보조 결과이며 침해·루프 확정 판정이 아닙니다.']:story.append(p('- '+str(value)))
 story.append(PageBreak());heading('4. 조사에 사용한 근거 요약')
 evidence=payload.get('evidence',{})
 for key,value in evidence.items():
  if not key.startswith('observation:') or not isinstance(value,dict):continue
  ident=key.split(':',1)[1];cur=value.get('current',{});base=value.get('baseline',{})
  heading(labels.get(ident,ident));story.append(p('근거 ID: '+key,'small'))
  def gb(n):return '{:,.3f} GB'.format((n or 0)/1e9)
  rows=[['항목','관측값'],['역할',value.get('role','미확인')],['조사 구간',stamp(value.get('window_start'))+' ~ '+stamp(value.get('window_end'))],['최근 수집',stamp(value.get('last_seen'))],['표본 수 / 유효 측정 시간',str(cur.get('samples',0))+'개 / '+str(cur.get('covered_seconds',0))+'초'],['보낸 양 / 받은 양',gb(cur.get('tx_bytes'))+' / '+gb(cur.get('rx_bytes'))],['최대 송신 / 수신 속도',str(cur.get('peak_tx_mbps','미측정'))+' / '+str(cur.get('peak_rx_mbps','미측정'))+' Mbps'],['최대 CPU / 메모리 / 디스크 공간 사용률',' / '.join(str(cur.get(k))+'%' if cur.get(k) is not None else '미측정' for k in ('max_cpu','max_memory','max_disk'))],['과거 기준선',('직전 6시간' if payload.get('network_report') else str(value.get('baseline_days',0))+'일')+' · '+str(base.get('samples',0))+'개 표본'],['연결 / 자원 수집 오류',str(cur.get('connection_errors',0))+' / '+str(cur.get('resource_errors',0))+'회']]
  expected=evidence.get('expected:'+ident,{})
  rows.append(['등록된 정상 작업 시간 (한국 시간)','백업: '+(', '.join(map(str,expected.get('backup_hours',[]))) or '없음')+' / 점검: '+(', '.join(map(str,expected.get('maintenance_hours',[]))) or '없음')])
  table(rows,[58*mm,116*mm])
 if not evidence:story.append(p('저장된 조사 근거가 없습니다.'))
 story.append(p('통신량은 장비 전체의 인터넷·내부망 합계입니다. 내부 통신은 양쪽 장비에 집계될 수 있습니다. 목적지별 상세 자료와 전체 원본 기록은 대시보드의 근거·로그 내려받기(JSON)에서 확인하세요.','small'))
 story.append(PageBreak());heading('5. Agent 주요 작업')
 if payload.get('agent_id'):story.append(p('Agent ID: '+payload['agent_id'],'small'))
 if payload.get('session_id'):story.append(p('Session ID: '+payload['session_id'],'small'))
 trace=payload.get('trace_summary',[])
 if trace:
  rows=[['시각 (한국 시간)','주요 작업','결과 및 상세']]
  for item in trace:
   detail=str(item.get('detail',''))
   if item.get('status'):detail+='\n상태: '+{'running':'시작','completed':'완료','failed':'실패'}.get(item['status'],item['status'])
   if item.get('duration_ms') is not None:detail+=' · 처리 '+str(item['duration_ms'])+'ms'
   rows.append([stamp(item.get('time')),str(item.get('action',''))+('\n'+item['tool'] if item.get('tool') else ''),detail])
  table(rows,[36*mm,52*mm,86*mm],compact=True)
 else:story.append(p('저장된 실행 로그가 없습니다.'))
 def footer(c,doc):
  c.saveState();c.setStrokeColor(colors.HexColor('#DDE4EE'));c.line(18*mm,16*mm,192*mm,16*mm)
  c.setFont('NCRegular',8);c.setFillColor(muted);c.drawString(18*mm,11*mm,'NetChecker | 담당자 검토용');c.drawRightString(192*mm,11*mm,str(doc.page)+'페이지');c.restoreState()
 doc=SimpleDocTemplate(output,pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=17*mm,bottomMargin=23*mm,title='NetChecker '+report.get('day','')+' 네트워크 환경 조사 보고서',author='NetChecker')
 doc.build(story,onFirstPage=footer,onLaterPages=footer)
 return output.getvalue()
