import urllib.request
import zipfile
import os
import shutil

def run():
    print("Downloading zip...")
    url = 'https://github.com/wyf295/LibScan/archive/refs/heads/master.zip'
    path = 'libscan.zip'
    urllib.request.urlretrieve(url, path)
    
    print("Extracting...")
    with zipfile.ZipFile(path, 'r') as zip_ref:
        zip_ref.extractall('extracted')
        
    print("Copying ground_truth_libs_dex...")
    src = 'extracted/LibScan-master/data/ground_truth_libs_dex'
    dst = 'third_party/libscan/data/ground_truth_libs_dex'
    os.makedirs(dst, exist_ok=True)
    
    for f in os.listdir(src):
        shutil.copy2(os.path.join(src, f), os.path.join(dst, f))
        
    print("Done")

if __name__ == "__main__":
    run()
