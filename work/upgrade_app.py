from pathlib import Path

path = Path('frontend/src/App.tsx')
source = path.read_text(encoding='utf-8')

def replace(old, new, count=1):
    global source
    if source.count(old) < count:
        raise SystemExit(f'Expected text not found {count} time(s): {old[:100]!r}')
    source = source.replace(old, new, count)

replace(" SECURITY OVERVIEW</div><h1>Good to see you, developer.</h1><p>Your code deserves a second set of eyes. Start a scan to catch issues early.",
        " LOCAL SECURITY WORKSPACE</div><h1>Project security overview</h1><p>Review the latest completed scan for each project. A finding marked reviewed is not necessarily fixed.")
replace('value={projects.length}note="Across your workspace"', 'value={dataLoading?\'—\':latestScans.length}note="Projects with a completed scan"')
replace('label="Total findings"value={total}note="From completed scans"', 'label="Latest findings"value={dataLoading?\'—\':total}note="Latest completed scan per project"')
replace('<Stat icon={<TriangleAlert/>}label="Critical & high"value={high}note="Review these first" red/>',
        '<Stat icon={<Activity/>}label="Awaiting review"value={dataLoading?\'—\':awaiting}note="From latest scans"/><Stat icon={<TriangleAlert/>}label="Critical & high"value={dataLoading?\'—\':high}note="Latest scans · review first" red/>')
replace('note={scans[0]?.project_name||\'No scans yet\'}', 'note={scans[0]?.started_at?new Date(scans[0].started_at).toLocaleString():"No scans yet"}')
replace('<p>Aggregated across completed scans</p></div><span className="tag">ALL SCANS</span>', '<p>Latest completed scan per project; rescans are not double-counted</p></div><span className="tag">{latestScans.length} PROJECTS</span>')
replace('{total?<ResponsiveContainer', '{dataLoading?<div className="empty-chart"><Activity/><strong>Loading scan data…</strong></div>:total?<ResponsiveContainer', 1)
replace('<Bar dataKey="count" fill="#4de0b0"', '<Bar dataKey="count" fill="#39ff88"', 1)
replace('<strong>No scan data yet</strong><span>Run your first scan to see security insights here.</span>', '<strong>No completed scan data yet</strong><span>Run your first scan to see security insights here.</span>', 1)
replace('<div className="panel table-wrap">{scans.length?<table>', '<div className="panel table-wrap">{dataLoading?<div className="empty-row">Loading scans…</div>:scans.length?<table>', 1)

replace('<label className="field-label">PROJECT NAME</label><input className="input" placeholder="e.g. storefront-api" value={name} onChange={e=>setName(e.target.value)}/><label className="field-label mt">PROJECT ARCHIVE</label>',
'''<label className="field-label" htmlFor="project-choice">PROJECT TARGET</label><select id="project-choice" className="input" value={projectChoice} onChange={e=>setProjectChoice(e.target.value)}><option value="new">Create a new project</option>{projects.map(p=><option value={p.id} key={p.id}>{p.name} · {p.scans_count} scans</option>)}</select>{projectChoice==='new'&&<><label className="field-label mt" htmlFor="project-name">PROJECT NAME</label><input id="project-name" className="input" placeholder="e.g. storefront-api" value={name} onChange={e=>setName(e.target.value)}/></>}<label className="field-label mt" htmlFor="project-archive">PROJECT ARCHIVE</label>''')
replace('<label className="dropzone"><UploadCloud', '<label className="dropzone" htmlFor="project-archive"><UploadCloud')
replace('<input type="file" accept=".zip,application/zip"', '<input id="project-archive" aria-label="Choose project ZIP archive" type="file" accept=".zip,application/zip"')
replace('<div className="progress-track"><span style={{width:selected?.status===\'completed\'?\'100%\':selected?.status===\'running\'?\'55%\':selected?.status===\'failed\'?\'100%\':\'8%\'}}/></div>',
        '<div className={\'progress-track \'+(selected?.status||\'queued\')} role="img" aria-label={selected?.status===\'running\'?\'Scan is running\':\'Scan status: \'+(selected?.status||\'queued\')}><span/></div>')

replace("desc={selected?`Results for ${selected.project_name}`:'Open a completed scan from Scan History to review its findings.'}",
        "desc=\"Investigate evidence-backed potential issues across your projects. Reviewed does not mean resolved.\"")
replace('<div className="searchbox"><Search size={16}/><input placeholder="Search findings…"', '<div className="searchbox"><Search size={16}/><input aria-label="Search findings by title, rule, or file" placeholder="Search findings…"')
replace('<select value={severity} onChange={e=>setSeverity(e.target.value)}><option>All</option>{[\'Critical\',\'High\',\'Medium\',\'Low\',\'Informational\'].map(x=><option key={x}>{x}</option>)}</select><span className="muted">{filtered.length} results</span>',
'''<select aria-label="Filter by severity" value={severity} onChange={e=>setSeverity(e.target.value)}><option>All</option>{['Critical','High','Medium','Low','Informational'].map(x=><option key={x}>{x}</option>)}</select><select aria-label="Filter by category" value={category} onChange={e=>setCategory(e.target.value)}><option>All</option>{[...new Set(findings.map(f=>f.category))].map(x=><option key={x}>{x}</option>)}</select><select aria-label="Filter by project" value={projectFilter} onChange={e=>setProjectFilter(e.target.value)}><option value="All">All projects</option>{projects.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select><select aria-label="Filter by review status" value={reviewFilter} onChange={e=>setReviewFilter(e.target.value)}><option>All</option><option>Open</option><option>Reviewed</option></select><span className="muted">{filtered.length} results</span>''')
replace("{selected?<FindingTable items={filtered} onOpen={setDetail}/>:<div className=\"panel empty-row\">Choose a scan from <button className=\"inline\" onClick={()=>go('Scan History')}>Scan History</button> to view results.</div>}",
        "{dataLoading?<div className=\"panel empty-row\">Loading findings…</div>:<FindingTable items={filtered} onOpen={setDetail}/>}")

replace('<th>PROJECT</th><th>STATUS</th><th>FINDINGS</th><th>FILES</th><th>STARTED</th><th>REPORT</th>', '<th>PROJECT</th><th>STATUS</th><th>FINDINGS</th><th>FILES</th><th>DURATION</th><th>STARTED</th><th>REPORT</th>')
replace('<td>{s.files_processed}</td><td>{new Date(s.started_at).toLocaleString()}</td><td><a className="download"', '<td>{s.files_processed}</td><td>{s.duration_seconds==null?\'—\':`${s.duration_seconds}s`}</td><td><code>{new Date(s.started_at).toLocaleString()}</code></td><td><a className="download"')

replace("<PageTitle eyebrow=\"ACTIVITY\" title=\"Scan history\" desc=\"A persistent record of projects you have scanned.\"/>",
'''<PageTitle eyebrow="ACTIVITY" title="Scan history" desc="A persistent record of project scans. Compare completed scans from the same project."/><div className="compare-tools"><label>COMPARE PROJECT SCANS</label><select aria-label="First scan to compare" value={compareFirst} onChange={e=>{setCompareFirst(e.target.value);setComparison(null)}}><option value="">Select a baseline scan</option>{scans.filter(s=>s.status==='completed').map(s=><option key={s.id} value={s.id}>{s.project_name} · {new Date(s.started_at).toLocaleString()} · {s.id.slice(0,8)}</option>)}</select><select aria-label="Second scan to compare" value={compareSecond} onChange={e=>{setCompareSecond(e.target.value);setComparison(null)}}><option value="">Select a later scan</option>{scans.filter(s=>s.status==='completed'&&(!compareFirst||s.project_id===scans.find(x=>x.id===compareFirst)?.project_id)).map(s=><option key={s.id} value={s.id}>{s.project_name} · {new Date(s.started_at).toLocaleString()} · {s.id.slice(0,8)}</option>)}</select><button className="secondary" disabled={!compareFirst||!compareSecond||compareFirst===compareSecond} onClick={doCompare}>Compare</button>{comparison&&<p className="comparison-result">{comparison.introduced.length} new · {comparison.unchanged} persistent · {comparison.not_detected_in_latest.length} no longer detected <small>“No longer detected” does not verify a fix.</small></p>}</div>''')

replace("{page==='Settings'&&<>", '''{page==='Reports'&&<><PageTitle eyebrow="EXPORTS" title="Scan reports" desc="Download reports from completed and incomplete scan records."/><div className="panel table-wrap">{scans.length?<table><thead><tr><th>PROJECT</th><th>SCAN ID</th><th>STATUS</th><th>FINDINGS</th><th>REPORTS</th></tr></thead><tbody>{scans.map(s=><tr key={s.id}><td>{s.project_name}</td><td><code>{s.id.slice(0,12)}</code></td><td><span className={'status '+s.status}>{s.status}</span></td><td>{s.findings_count}</td><td><a className="download" href={`${API}/scans/${s.id}/report.json`}>JSON <ExternalLink size={13}/></a> · <a className="download" target="_blank" rel="noreferrer" href={`${API}/scans/${s.id}/report.html`}>HTML</a></td></tr>)}</tbody></table>:<div className="empty-row">Reports appear after your first scan.</div>}</div></>}{page==='Settings'&&<>''')

replace('<div className="overlay" onClick={()=>setDetail(null)}><aside className="detail-drawer" onClick={e=>e.stopPropagation()}><button className="close" onClick={()=>setDetail(null)}>×</button>',
        '<div className="overlay" onClick={()=>setDetail(null)}><aside className="detail-drawer" role="dialog" aria-modal="true" aria-label={detail.title} onClick={e=>e.stopPropagation()}><button className="close" aria-label="Close finding details" onClick={()=>setDetail(null)}>×</button>')
replace('{detail.references?.map(r=><a className="download" target="_blank" rel="noreferrer" href={r} key={r}>Reference', '{detail.references?.filter(r=>r.startsWith(\'https://\')).map(r=><a className="download" target="_blank" rel="noreferrer" href={r} key={r}>Reference')
replace('<button className="primary wide review-btn" onClick={()=>mark(detail)}>', '<p className="review-note">Review is a triage state only; DevGuard does not verify whether a finding has been fixed.</p><button className="primary wide review-btn" onClick={()=>mark(detail)}>')

replace('<tr key={f.id} onClick={()=>onOpen(f)}>', '<tr key={f.id} role="button" tabIndex={0} aria-label={`Open finding ${f.title}`} onKeyDown={e=>{if(e.key===\'Enter\'||e.key===\' \'){e.preventDefault();onOpen(f)}}} onClick={()=>onOpen(f)}>')
replace('<th>SEVERITY</th><th>FINDING</th><th>CATEGORY</th><th>LOCATION</th><th>REVIEW</th>', '<th>SEVERITY</th><th>RULE / FINDING</th><th>PROJECT / SCAN</th><th>CATEGORY</th><th>LOCATION</th><th>REVIEW</th>')
replace('<td><strong>{f.title}</strong><small className="subline">{f.rule_id}</small></td><td>{f.category}</td>', '<td><strong>{f.title}</strong><small className="subline">{f.rule_id}</small></td><td>{f.project_name||\'Current scan\'}<small className="subline mono">{f.scan_id?.slice(0,8)||\'—\'}</small></td><td>{f.category}</td>')
replace('function FindingTable({items,onOpen}:any){return', 'function FindingTable({items,onOpen}:any){return')

path.write_text(source, encoding='utf-8')
