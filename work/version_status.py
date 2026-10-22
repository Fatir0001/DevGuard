from pathlib import Path
p=Path('frontend/src/App.tsx');s=p.read_text(encoding='utf-8')
changes=[
 ("[apiUp,setApiUp]=useState(false),[compareFirst", "[apiUp,setApiUp]=useState(false),[scannerVersion,setScannerVersion]=useState('unknown'),[compareFirst"),
 ("const[s,p]=await Promise.all([req('/scans?limit=200'),req('/projects')]);setScans(s.items);setProjects(p.items);setApiUp(true);", "const[s,p,h]=await Promise.all([req('/scans?limit=1000'),req('/projects'),req('/health')]);setScans(s.items);setProjects(p.items);setScannerVersion(h.scanner_version||'unknown');setApiUp(true);"),
 ("<small>v1.0.0</small>", "<small>v{scannerVersion}</small>"),
 ("<span className=\"online-dot\"/>", "<span className={apiUp?'online-dot':'offline-dot'}/>")
]
for old,new in changes:
 if old not in s: raise SystemExit(f'Missing {old!r}')
 s=s.replace(old,new,1)
p.write_text(s,encoding='utf-8')
