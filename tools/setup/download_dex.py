import urllib.request
import json
import os
import time

def download_file(url, path):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return
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
    print(f"Failed to download {url}")

def run():
    target_dir = 'third_party/libscan/data/ground_truth_libs_dex'
    os.makedirs(target_dir, exist_ok=True)
    req = urllib.request.Request('https://api.github.com/repos/wyf295/LibScan/contents/data/ground_truth_libs_dex')
    req.add_header("User-Agent", "Mozilla/5.0")
    with urllib.request.urlopen(req) as response:
        contents = json.loads(response.read().decode())
        
    for item in contents:
        if item['type'] == 'file':
            path = os.path.join(target_dir, item['name'])
            download_file(item['download_url'], path)

if __name__ == "__main__":
    run()
    print("Done")
