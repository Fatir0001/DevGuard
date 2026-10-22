from pathlib import Path
p=Path('frontend/src/App.tsx');s=p.read_text(encoding='utf-8')
changes=[
 ("[file,setFile]=useState<File|null>(null),[collapsed", "[file,setFile]=useState<File|null>(null),[uploadMeta,setUploadMeta]=useState<{name:string;size:number}|null>(null),[collapsed"),
 ("const d=new FormData();if(projectChoice==='new')d.append('name',name);else d.append('project_id',projectChoice);d.append('project',file);const x=await req('/scans',{method:'POST',body:d});const s=await req('/scans/'+x.scan_id);", "const d=new FormData();if(projectChoice==='new')d.append('name',name);else d.append('project_id',projectChoice);d.append('project',file);setUploadMeta({name:file.name,size:file.size});const x=await req('/scans',{method:'POST',body:d});setFile(null);const s=await req('/scans/'+x.scan_id);"),
 ("<p>{selected?.error||'Analysis runs in a bounded local background worker.'}</p>", "<p>{selected?.error||'Analysis runs in a bounded local background worker.'}{uploadMeta&&<> · Archive: <code>{uploadMeta.name}</code> · {(uploadMeta.size/1024/1024).toFixed(1)} MB</>}</p>")
]
for a,b in changes:
 if a not in s: raise SystemExit(f'Missing {a[:100]!r}')
 s=s.replace(a,b,1)
p.write_text(s,encoding='utf-8')
