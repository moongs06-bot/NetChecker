"""Presentation-only address policy; raw telemetry remains available for analysis."""
import ipaddress


def visible_ipv4(values):
    result=[]
    for value in values or []:
        try:
            address=ipaddress.ip_address(value)
            if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped:
                address=address.ipv4_mapped
            if address.version==4 and address.packed[0]!=169 and str(address) not in result:
                result.append(str(address))
        except (ValueError,TypeError):
            pass
    return result


def sanitize(value):
    if isinstance(value,list):
        return [sanitize(x) for x in value]
    if not isinstance(value,dict):
        return value
    result={}
    for key,item in value.items():
        if key in ('mac','macs','mac_address'):
            continue
        if key=='ips':
            # Preserve pseudonymous evidence identifiers, never reinterpret them as IPs.
            result[key]=[x for x in item if isinstance(x,str) and x.startswith('ip-')]+visible_ipv4(item)
        elif key in ('ip','server_ip','source_ip','destination_ip','local_ip','remote_ip'):
            try:
                ipaddress.ip_address(item)
            except (ValueError,TypeError):
                result[key]=item
            else:
                result[key]=next(iter(visible_ipv4([item])),'표시할 IPv4 없음')
        else:
            result[key]=sanitize(item)
    return result
