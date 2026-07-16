import urllib.request
import json
import os
import time

def download_file(url, path):
    print(f"Downloading {path}...")
    for _ in range(3):
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=15) as response:
                with open(path, 'wb') as f:
                    f.write(response.read())
            return
        except Exception as e:
            print(f"Retry {url}: {e}")
            time.sleep(1)
    raise Exception(f"Failed to download {url}")

def get_tree(api_url, target_dir):
    os.makedirs(target_dir, exist_ok=True)
    req = urllib.request.Request(api_url)
    req.add_header("User-Agent", "Mozilla/5.0")
    with urllib.request.urlopen(req) as response:
        contents = json.loads(response.read().decode())
        
    for item in contents:
        path = os.path.join(target_dir, item['name'])
        if item['type'] == 'dir':
            get_tree(item['url'], path)
        elif item['type'] == 'file':
            download_file(item['download_url'], path)

if __name__ == "__main__":
    get_tree('https://api.github.com/repos/wyf295/LibScan/contents/tool', 'third_party/libscan/tool')
    download_file('https://raw.githubusercontent.com/wyf295/LibScan/master/README.md', 'third_party/libscan/README.md')
    print("Done")
