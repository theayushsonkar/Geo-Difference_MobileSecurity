import base64
import re
from pathlib import Path

def parse_sdns(stamp):
    try:
        b = base64.urlsafe_b64decode(stamp + "===")
        proto = b[0]
        addr_len = b[9]
        addr = b[10:10+addr_len].decode('utf-8')
        
        ip = addr
        # Remove port if present
        if ip.startswith('['):
            ip = ip[1:ip.find(']')]
        else:
            if ':' in ip and not ip.count(':') > 1:
                ip = ip.split(':')[0]
            
        return proto, ip
    except Exception as e:
        return None, None

def parse_md(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    blocks = content.split('\n## ')
    
    resolvers = []
    
    for block in blocks[1:]: # Skip header
        lines = block.split('\n')
        name = lines[0].strip()
        provider = ""
        ips = set()
        supports_doh = False
        supports_dnscrypt = False
        
        for line in lines[1:]:
            if line.startswith('Operated by'):
                provider = line.split('Operated by')[1].split('.')[0].strip()
            
            if line.startswith('sdns://'):
                stamp = line[7:]
                proto, ip = parse_sdns(stamp)
                if not ip:
                    continue
                    
                if proto == 1:
                    supports_dnscrypt = True
                elif proto == 2:
                    supports_doh = True
                    
                ips.add(ip)
                
        if ips:
            resolvers.append({
                "resolver_name": name,
                "provider": provider or "Unknown",
                "ips": list(ips),
                "supports_doh": supports_doh,
                "supports_dnscrypt": supports_dnscrypt,
                "supports_dot": False # dnscrypt-resolvers doesn't track DoT
            })
            
    return resolvers

res = parse_md(r"C:\Users\Ayush Sonkar\.gemini\antigravity\brain\4152d2b8-0cdb-46c4-a158-344d9fda0cc9\.system_generated\steps\1166\content.md")
for r in res[:10]:
    print(r)
print(f"Total resolvers: {len(res)}")
