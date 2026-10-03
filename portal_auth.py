"""Admin browser sessions; device bearer authentication stays separate."""
import base64,hashlib,hmac,json,os,secrets,time
from fastapi import Request,HTTPException
from fastapi.responses import HTMLResponse,JSONResponse,FileResponse
from pydantic import BaseModel,Field,ConfigDict

COOKIE='nc_session'
def credentials(s):
    conf=json.loads(s.CONFIG.read_text(encoding='utf-8-sig'))
    path=s.STATE/'admin_credentials.json'
    if path.exists():conf.update(json.loads(path.read_text()))
    return conf
def matches(conf,user,password):
    value=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(conf['admin_salt']),200000).hex()
    return hmac.compare_digest(user,conf['admin_user']) and hmac.compare_digest(value,conf['admin_hash'])
def init(s):
    with s.db() as c:c.execute('CREATE TABLE IF NOT EXISTS admin_sessions(token TEXT PRIMARY KEY,expires REAL,version TEXT)')
def guard(s,request):
    conf=credentials(s);token=request.cookies.get(COOKIE);valid=False
    if token:
        with s.db() as c:r=c.execute('SELECT expires,version FROM admin_sessions WHERE token=?',(s.digest(token),)).fetchone()
        valid=bool(r and r['expires']>time.time() and hmac.compare_digest(r['version'],conf['admin_hash']))
    elif request.headers.get('authorization','').startswith('Basic ') and request.cookies.get('nc_logged_out')!='1':
        try:
            user,password=base64.b64decode(request.headers['authorization'][6:],validate=True).decode().split(':',1)
            valid=matches(conf,user,password)
        except Exception:pass
    if not valid:
        s.budget('auth:'+request.client.host,20,60)
        raise HTTPException(401,'로그인이 필요합니다.')
    if request.method not in ('GET','HEAD'):mutation(request)
def mutation(request):
    if request.headers.get('x-netchecker')!='1':raise HTTPException(403,'요청 출처 확인 실패')
    origin=request.headers.get('origin')
    if origin:
        from urllib.parse import urlsplit
        if urlsplit(origin).netloc!=request.headers.get('host'):raise HTTPException(403,'다른 사이트에서 요청할 수 없습니다.')
class Login(BaseModel):
    model_config=ConfigDict(extra='forbid')
    username:str=Field(min_length=1,max_length=100)
    password:str=Field(min_length=1,max_length=256)
class Password(BaseModel):
    model_config=ConfigDict(extra='forbid')
    current:str=Field(min_length=1,max_length=256)
    password:str=Field(min_length=12,max_length=128)
def install(s):
    @s.app.get('/login',response_class=HTMLResponse)
    async def login_page():return (s.ROOT/'login.html').read_text(encoding='utf-8')
    @s.app.post('/api/login')
    async def login(body:Login,request:Request):
        mutation(request);s.budget('login:'+request.client.host,10,60);conf=credentials(s)
        if not matches(conf,body.username,body.password):raise HTTPException(401,'아이디 또는 비밀번호를 확인해주세요.')
        token=secrets.token_urlsafe(40)
        with s.db() as c:
            c.execute('DELETE FROM admin_sessions WHERE expires<?',(time.time(),))
            c.execute('INSERT INTO admin_sessions VALUES(?,?,?)',(s.digest(token),time.time()+8*3600,conf['admin_hash']))
        response=JSONResponse({'ok':True});response.set_cookie(COOKIE,token,max_age=8*3600,httponly=True,secure=True,samesite='strict',path='/')
        response.delete_cookie('nc_logged_out',path='/');s.audit('admin_login','admin');return response
    @s.app.post('/api/logout')
    async def logout(request:Request):
        mutation(request)
        with s.db() as c:c.execute('DELETE FROM admin_sessions WHERE token=?',(s.digest(request.cookies.get(COOKIE,'')),))
        response=JSONResponse({'ok':True});response.delete_cookie(COOKIE,path='/');response.set_cookie('nc_logged_out','1',secure=True,httponly=True,samesite='strict',path='/');return response
    @s.app.post('/api/password')
    async def password(body:Password,request:Request):
        s.admin(request);s.budget('password:'+request.client.host,5,60);conf=credentials(s)
        if not matches(conf,conf['admin_user'],body.current):raise HTTPException(400,'현재 비밀번호가 맞지 않습니다.')
        if body.password==body.current:raise HTTPException(400,'새 비밀번호를 다르게 입력해주세요.')
        salt=secrets.token_hex(16);value={'admin_user':conf['admin_user'],'admin_salt':salt,'admin_hash':hashlib.pbkdf2_hmac('sha256',body.password.encode(),bytes.fromhex(salt),200000).hex()}
        target=s.STATE/'admin_credentials.json';temp=s.STATE/'admin_credentials.pending'
        temp.write_text(json.dumps(value));os.chmod(temp,0o600);os.replace(temp,target)
        with s.db() as c:c.execute('DELETE FROM admin_sessions')
        s.audit('admin_password_changed','admin');response=JSONResponse({'ok':True});response.delete_cookie(COOKIE,path='/');response.set_cookie('nc_logged_out','1',secure=True,httponly=True,samesite='strict',path='/');return response
    @s.app.get('/portal.css')
    async def style():return FileResponse(s.ROOT/'portal.css',media_type='text/css')
    @s.app.get('/portal.js')
    async def script(request:Request):s.admin(request);return FileResponse(s.ROOT/'portal.js',media_type='application/javascript')
