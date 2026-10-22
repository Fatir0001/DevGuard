from pathlib import Path
p=Path('frontend/src/App.tsx')
s=p.read_text(encoding='utf-8')
def rep(old,new):
    global s
    if old not in s: raise SystemExit(f'Missing: {old[:90]!r}')
    s=s.replace(old,new,1)
rep("const go=async(p:string)=>{setPage(p);setErr('');if(p==='Findings'){try{setFindings((await req('/findings?limit=1000')).items)}catch(e){setErr(String(e))}}};",
    "const go=async(p:string)=>{setPage(p);setErr('');if(p==='Findings'){setDataLoading(true);try{setFindings((await req('/findings?limit=1000')).items)}catch(e){setErr(String(e))}finally{setDataLoading(false)}}};")
rep('<span className="connection"><i/>{apiUp?', '<span className={\'connection \'+(apiUp?\'online\':\'offline\')}><i/>{apiUp?')
rep('{err}<button onClick={()=>setErr(\'\')}>×</button>', '{err}<button className="retry" onClick={refresh}>Retry</button><button aria-label="Dismiss message" onClick={()=>setErr(\'\')}>×</button>')
rep('<div className="detail-block"><span>LOCATION</span>', '<div className="detail-block"><span>PROJECT · SCAN</span><code>{detail.project_name||selected?.project_name||\'Current project\'} · {detail.scan_id?.slice(0,12)||selected?.id?.slice(0,12)||\'—\'}</code></div><div className="detail-block"><span>CATEGORY</span><code>{detail.category}</code></div><div className="detail-block"><span>LOCATION</span>')
rep('desc="Upload a project archive and DevGuard will analyze it safely. Your code is never executed."', 'desc="Choose an existing project to add a comparable scan, or create a project. Archives are inspected as data; project code is never run."')
rep("Upload a ZIP from your computer", "Upload a ZIP from your computer")
rep('onClick={()=>{setSelected(s);setPage(\'Scan progress\')}}', 'onClick={()=>{setSelected(s);setPage(\'Scan progress\')}}')
p.write_text(s,encoding='utf-8')
