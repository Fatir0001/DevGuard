from pathlib import Path
p=Path('frontend/src/App.tsx');s=p.read_text(encoding='utf-8')
changes=[
 ("confidence:string;project_name?:string;", "confidence:string;cve?:string;source_severity?:string;affected_ranges?:any[];project_name?:string;"),
 ("useEffect(()=>{refresh()},[]);", "useEffect(()=>{refresh()},[]);useEffect(()=>{if(!detail)return;const onKey=(event:KeyboardEvent)=>{if(event.key==='Escape')setDetail(null)};window.addEventListener('keydown',onKey);return()=>window.removeEventListener('keydown',onKey)},[detail]);"),
 ("<span className={'severity '+detail.severity.toLowerCase()}>{detail.severity}</span><h2>", "<span className={'severity '+detail.severity.toLowerCase()}>{detail.severity}</span><span className=\"finding-kind\">{detail.rule_id==='OSV'?'KNOWN ADVISORY · OSV':'HEURISTIC PATTERN'}</span><h2>"),
 ("<div className=\"detail-block\"><span>CATEGORY</span><code>{detail.category}</code></div><div className=\"detail-block\"><span>LOCATION</span>", "<div className=\"detail-block\"><span>SCAN DATE</span><code>{detail.scan_started_at?new Date(detail.scan_started_at).toLocaleString():selected?.started_at?new Date(selected.started_at).toLocaleString():'—'}</code></div><div className=\"detail-block\"><span>CATEGORY</span><code>{detail.category}</code></div><div className=\"detail-block\"><span>LOCATION</span>"),
 ("{detail.advisory_id&&<div className=\"detail-block\"><span>ADVISORY</span><code>{detail.advisory_id}</code></div>}", "{(detail.advisory_id||detail.cve)&&<div className=\"detail-block\"><span>VERIFIED ADVISORY IDENTIFIERS</span><code>{detail.cve||detail.advisory_id} {detail.cve&&detail.advisory_id&&'· '+detail.advisory_id}</code>{detail.source_severity&&<small>Source severity: {detail.source_severity}</small>}</div>}{detail.affected_ranges?.length&&<div className=\"detail-block\"><span>ADVISORY AFFECTED RANGES</span><pre>{JSON.stringify(detail.affected_ranges,null,2)}</pre></div>}"),
]
for a,b in changes:
 if a not in s: raise SystemExit(f'Missing {a[:90]!r}')
 s=s.replace(a,b,1)
p.write_text(s,encoding='utf-8')
