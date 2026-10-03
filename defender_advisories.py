"""Official advisories are reference data, never executable instructions."""
import asyncio,json,re,urllib.request
from datetime import datetime,timezone,timedelta
from fastapi import Request,HTTPException
URL='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
def install(s):
 @s.app.get('/api/defender/advisories')
 async def advisories(request:Request):
  s.admin(request);path=s.STATE/'defender-advisories.json'
  if path.exists():
   value=json.loads(path.read_text())
   if datetime.now(timezone.utc)-datetime.fromisoformat(value['checked_at'])<timedelta(hours=6):return value
  def fetch():
   req=urllib.request.Request(URL,headers={'User-Agent':'NetChecker-Defender/0.2'})
   with urllib.request.urlopen(req,timeout=15) as response:data=response.read(5_000_001)
   if len(data)>5_000_000:raise ValueError('Feed too large')
   catalog=json.loads(data);items=[]
   for item in sorted(catalog.get('vulnerabilities',[]),key=lambda i:i.get('dateAdded',''),reverse=True):
    cve=item.get('cveID','')
    if item.get('vendorProject')!='Microsoft' or not re.fullmatch(r'CVE-\d{4}-\d{4,8}',cve):continue
    items.append({'cve':cve,'product':str(item.get('product',''))[:150],'name':str(item.get('vulnerabilityName',''))[:300],'added':str(item.get('dateAdded',''))[:20],'required_action':str(item.get('requiredAction',''))[:500]})
    if len(items)>=10:break
   return {'checked_at':s.now(),'source':'CISA Known Exploited Vulnerabilities','source_url':'https://www.cisa.gov/known-exploited-vulnerabilities-catalog','items':items,'limitation':'일반 보안 권고입니다. 이 장비의 취약 여부나 패치 적용 필요성을 확정하지 않습니다. 적용 가능 항목은 Windows Update 조회로 확인하세요.'}
  try:value=await asyncio.to_thread(fetch)
  except Exception:
   if path.exists():value=json.loads(path.read_text());value['stale']=True;return value
   raise HTTPException(502,'공식 보안 권고 자료를 확인하지 못했습니다.')
  path.write_text(json.dumps(value,ensure_ascii=False));return value
