import urllib.request
import os

os.makedirs('knowledge_base/raw/easyprivacy', exist_ok=True)
req = urllib.request.Request(
    'https://easylist.to/easylist/easyprivacy.txt',
    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
)
with urllib.request.urlopen(req) as response:
    content = response.read()
    
with open('knowledge_base/raw/easyprivacy/easyprivacy.txt', 'wb') as f:
    f.write(content)
print("Downloaded EasyPrivacy.")
