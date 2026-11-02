"""Clone every corpus repository at its frozen commit.
usage: python3 scripts/clone_corpus.py data/corpus/corpus_manifest.csv corpus/"""
import csv, os, subprocess, sys
manifest, dest = sys.argv[1], sys.argv[2]
os.makedirs(dest, exist_ok=True)
for r in csv.DictReader(open(manifest)):
    d = os.path.join(dest, r["repo_dir"])
    if os.path.isdir(d):
        continue
    subprocess.run(["git", "init", "-q", d], check=True)
    subprocess.run(["git", "-C", d, "remote", "add", "origin", r["url"]], check=True)
    ok = subprocess.run(["git", "-C", d, "fetch", "-q", "--depth", "1", "origin", r["commit"]]).returncode == 0
    if ok:
        subprocess.run(["git", "-C", d, "checkout", "-q", "FETCH_HEAD"], check=True)
    else:
        print("unavailable:", r["url"], r["commit"])
