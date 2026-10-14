#!/usr/bin/env python3
"""Cross-document consistency check for segmentation_report.md, analysis.md and evidence_manifest.md.

Report tooling (not evidence). Known false positives: `6e3f7d37`, `fdbca74d` (nvram flags) and
`1978418030` (Hue firmware version) as "commit-like hashes"; analysis § refs 1.7/1.9/1.10 point to the
report; short file names in backticks resolve relative to their folders.
"""
import re, os, subprocess
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
docs = {p: open(p, encoding='utf-8').read() for p in ('segmentation_report.md', 'analysis.md', 'evidence_manifest.md')}
repo = 'asuswrt-configs'
def git_ok(h): return subprocess.run(['git', '-C', repo, 'cat-file', '-e', h + '^{commit}'], capture_output=True).returncode == 0
print('== commit-like hashes not in repo (backticked 7-12 hex)')
for p, s in docs.items():
    print(p, sorted({h for h in re.findall(r'`([0-9a-f]{7,12})`', s) if not git_ok(h)}))
print('== backticked paths that do not exist')
tracked = subprocess.run(['git', '-C', repo, 'ls-files'], capture_output=True, text=True).stdout.split()
names = {os.path.basename(t) for t in tracked}
for p, s in docs.items():
    miss = set()
    for m in re.findall(r'`([^`\s]+)`', s):
        if m.startswith(('/', 'http', '<', '$')) or '*' in m or '…' in m or '<' in m: continue
        if not re.search(r'\.(pcap|log|txt|csv|json|md|py|sh|zeek|env|CFG|tsv|xml|nmap|gnmap|postconf|conf|add)$|/$', m): continue
        cand = [m, m.rstrip('/'), os.path.join(repo, m), os.path.join(repo, 'scripts', m), os.path.join(repo, 'configs', m)]
        if any(os.path.exists(c) for c in cand) or os.path.basename(m.rstrip('/')) in names: continue
        miss.add(m)
    print(p, sorted(miss))
print('== E-IDs cited vs manifest')
man_ids = set(re.findall(r'^\| (E\d\d) \|', docs['evidence_manifest.md'], re.M))
for p in ('segmentation_report.md', 'analysis.md'):
    cited = set(re.findall(r'\bE\d\d\b', docs[p]))
    print(p, 'cited', len(cited), 'missing from manifest:', sorted(cited - man_ids))
print('== section refs')
def heads(s): return set(re.findall(r'^#{2,4} (\d+(?:\.\d+)*)[ .]', s, re.M))
ha, hr = heads(docs['analysis.md']), heads(docs['segmentation_report.md'])
print('analysis § refs missing:', sorted(r for r in set(re.findall(r'§(\d+(?:\.\d+)*)', docs['analysis.md'])) if r not in ha))
x1 = set(re.findall(r'segmentation_report\.md` ?§(\d+(?:\.\d+)*)', docs['analysis.md']))
x2 = set(re.findall(r'analysis §(\d+(?:\.\d+)*)', docs['segmentation_report.md']))
print('analysis->report missing:', sorted(r for r in x1 if r not in hr), ' report->analysis missing:', sorted(r for r in x2 if r not in ha))
r_in = set(re.findall(r'\((?:see )?(\d\.\d+)\)', docs['segmentation_report.md']))
print('report internal (x.y) refs missing:', sorted(r for r in r_in if r not in hr))
print('== recommendation refs in analysis')
a = docs['analysis.md']
recs = re.findall(r'^(\d+)\. ', a[a.index('## 10. Recommendations'):a.index('## 11.')], re.M)
print('recs defined:', recs, 'refs:', sorted(set(re.findall(r'[Rr]ecommendations? (\d+)', a)), key=int))
print('== leftovers')
for p, s in docs.items():
    print(p, 'D-substates:', len(re.findall('D[′″]', s)), 'strikethrough:', s.count('~~') if p == 'segmentation_report.md' else '-')
