from pathlib import Path
p=Path('frontend/src/App.tsx');s=p.read_text(encoding='utf-8')
def rep(a,b):
 global s
 if a not in s: raise SystemExit(f'Missing {a[:80]!r}')
 s=s.replace(a,b,1)
rep("setCompareFirst(e.target.value);setComparison(null)", "setCompareFirst(e.target.value);setCompareSecond('');setComparison(null)")
rep('{comparison&&<p className="comparison-result">{comparison.introduced.length} new · {comparison.unchanged} persistent · {comparison.not_detected_in_latest.length} no longer detected <small>“No longer detected” does not verify a fix.</small></p>}',
'''{comparison&&<div className="comparison-result"><strong>{comparison.introduced.length} introduced · {comparison.unchanged} persistent · {comparison.not_detected_in_latest.length} no longer detected</strong><small>Not detected in the latest scan does not verify a fix.</small>{comparison.introduced.map((f:any,i:number)=><div key={'new'+i}>NEW · {f.title} · {f.file_path||f.dependency_name||'project'}</div>)}{comparison.persistent.map((f:any,i:number)=><div key={'same'+i}>PERSISTENT · {f.title} · {f.file_path||f.dependency_name||'project'}</div>)}{comparison.not_detected_in_latest.map((f:any,i:number)=><div key={'old'+i}>NO LONGER DETECTED · {f.title} · {f.file_path||f.dependency_name||'project'}</div>)}</div>}''')
rep('<button className="icon-btn" onClick={()=>setCollapsed(!collapsed)}>', '<button className="icon-btn" aria-label={collapsed?\'Expand navigation\':\'Collapse navigation\'} onClick={()=>setCollapsed(!collapsed)}>')
rep('<button className="avatar">DG</button>', '<span className="avatar" aria-label="DevGuard local workspace">DG</span>')
rep("<div className=\"notice\"><TriangleAlert size={16}/>{err}<button className=\"retry\" onClick={refresh}>Retry</button><button aria-label=\"Dismiss message\" onClick={()=>setErr('')}>×</button></div>",
    "<div className=\"notice\"><TriangleAlert size={16}/>{err}{err.startsWith('API unavailable')&&<button className=\"retry\" onClick={refresh}>Retry connection</button>}<button aria-label=\"Dismiss message\" onClick={()=>setErr('')}>×</button></div>")
rep("<div className=\"overlay\" onClick={()=>setDetail(null)}>", "<div className=\"overlay\" onClick={()=>setDetail(null)}>")
p.write_text(s,encoding='utf-8')
