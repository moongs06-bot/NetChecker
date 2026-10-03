from datetime import datetime,timezone,timedelta
import ipaddress,uuid
from pydantic import BaseModel,ConfigDict,Field,field_validator,model_validator

def ip(value):
 address=ipaddress.ip_address(value)
 return str(address.ipv4_mapped if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped else address)
def timestamp(v):
 if v.tzinfo is None:raise ValueError('Timezone required')
 if not datetime.now(timezone.utc)-timedelta(days=2)<=v<=datetime.now(timezone.utc)+timedelta(minutes=5):raise ValueError('Timestamp outside accepted range')
 return v.astimezone(timezone.utc)
class Strict(BaseModel):model_config=ConfigDict(extra='forbid',allow_inf_nan=False)
class Flow(Strict):
 local_ip:str;remote_ip:str
 local_port:int=Field(ge=0,le=65535);remote_port:int=Field(ge=0,le=65535)
 protocol:str=Field(pattern='^(TCP|UDP)$')
 tx_bytes:int=Field(ge=0,le=10**13);rx_bytes:int=Field(ge=0,le=10**13)
 _ips=field_validator('local_ip','remote_ip')(ip)
class FlowWindow(Strict):
 window_id:uuid.UUID;started_at:datetime;ended_at:datetime
 lost_events:int=Field(ge=-1,le=10**12)
 truncated:bool;flows:list[Flow]=Field(max_length=300)
 _times=field_validator('started_at','ended_at')(timestamp)
 @model_validator(mode='after')
 def window(self):
  if not 0<(self.ended_at-self.started_at).total_seconds()<=180:raise ValueError('Invalid flow interval')
  return self
class PortEvent(Strict):
 record_id:str=Field(pattern=r'^\d{1,22}$');time:datetime
 source_ip:str;destination_ip:str
 source_port:int=Field(ge=0,le=65535);destination_port:int=Field(ge=0,le=65535)
 protocol:str=Field(pattern='^(TCP|UDP)$')
 action:str=Field(pattern='^(allowed|blocked)$')
 _ips=field_validator('source_ip','destination_ip')(ip)
 _time=field_validator('time')(timestamp)
class ServerPolicy(Strict):
 configured:bool=False
 tcp:list[int]=Field(default_factory=list,max_length=200)
 udp:list[int]=Field(default_factory=list,max_length=200)
 @field_validator('tcp','udp')
 @classmethod
 def ports(cls,v):
  if any(not 1<=p<=65535 for p in v):raise ValueError('Port must be 1-65535')
  return sorted(set(v))
