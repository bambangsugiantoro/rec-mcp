import json, re, os, sys, time, csv
sys.path.insert(0, 'analyzer'); sys.setrecursionlimit(5000)
from rec_analyzer import analyze_repo
pick = json.load(open('pilot_candidates.json'))
res = []
for cat, name, url in pick:
    m = re.match(r'https://github.com/([^/]+)/([^/#?]+)(?:/tree/[^/]+/(.*))?', url)
    owner, repo, sub = m.groups()
    dest = f'corpus/{owner}__{repo}'
    if not os.path.exists(dest): continue
    root = os.path.join(dest, sub) if sub else dest
    t = time.time()
    r = analyze_repo(root, f'{owner}/{repo}')
    r['category'] = cat; r['secs'] = round(time.time() - t, 2)
    res.append(r)
    print(f"{owner}/{repo:35} tools={r['n_tools']:3} sites={len(r['sites']):3} {r['secs']}s", flush=True)
json.dump(res, open('results/pilot_raw.json', 'w'), indent=1, ensure_ascii=False)
