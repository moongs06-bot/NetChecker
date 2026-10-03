"""Create local admin credentials without publishing passwords."""
import getpass,hashlib,json,secrets
from pathlib import Path
p=Path('config.json')
if p.exists():raise SystemExit('config.json exists; refusing overwrite')
pw=getpass.getpass('New administrator password (12+ chars): ')
if len(pw)<12:raise SystemExit('Password too short')
salt=secrets.token_hex(16)
c=json.loads(Path('config.example.json').read_text())
c.update(admin_salt=salt,admin_hash=hashlib.pbkdf2_hmac('sha256',pw.encode(),bytes.fromhex(salt),200000).hex())
p.write_text(json.dumps(c,indent=2),encoding='utf-8');p.chmod(0o600)
print('Created local config.json. Never commit it.')
