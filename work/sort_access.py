from pathlib import Path
p=Path('frontend/src/App.tsx');s=p.read_text(encoding='utf-8')
changes=[
 ("[reviewFilter,setReviewFilter]=useState('All'),[loading", "[reviewFilter,setReviewFilter]=useState('All'),[sortBy,setSortBy]=useState('latest'),[loading"),
 ("const filtered=useMemo(()=>findings.filter(f=>(severity==='All'||f.severity===severity)&&(category==='All'||f.category===category)&&(projectFilter==='All'||f.project_id===projectFilter)&&(reviewFilter==='All'||(reviewFilter==='Reviewed'?f.reviewed:!f.reviewed))&&(!query||`${f.title} ${f.rule_id} ${f.file_path} ${f.category} ${f.dependency_name}`.toLowerCase().includes(query.toLowerCase()))),[findings,severity,category,projectFilter,reviewFilter,query]);",
  "const filtered=useMemo(()=>findings.filter(f=>(severity==='All'||f.severity===severity)&&(category==='All'||f.category===category)&&(projectFilter==='All'||f.project_id===projectFilter)&&(reviewFilter==='All'||(reviewFilter==='Reviewed'?f.reviewed:!f.reviewed))&&(!query||`${f.title} ${f.rule_id} ${f.file_path} ${f.category} ${f.dependency_name}`.toLowerCase().includes(query.toLowerCase()))).sort((a,b)=>sortBy==='title'?a.title.localeCompare(b.title):sortBy==='severity'?['Critical','High','Medium','Low','Informational'].indexOf(a.severity)-['Critical','High','Medium','Low','Informational'].indexOf(b.severity):String(b.scan_started_at||'').localeCompare(String(a.scan_started_at||''))),[findings,severity,category,projectFilter,reviewFilter,query,sortBy]);"),
 ("<span className=\"muted\">{filtered.length} results</span>", "<select aria-label=\"Sort findings\" value={sortBy} onChange={e=>setSortBy(e.target.value)}><option value=\"latest\">Latest scan</option><option value=\"severity\">Severity</option><option value=\"title\">Title</option></select><span className=\"muted\">{filtered.length} results</span>")
]
for old,new in changes:
 if old not in s: raise SystemExit(f'Missing fragment: {old[:90]!r}')
 s=s.replace(old,new,1)
p.write_text(s,encoding='utf-8')
