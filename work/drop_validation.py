from pathlib import Path
p=Path('frontend/src/App.tsx');s=p.read_text(encoding='utf-8')
a="const mark=async(f:F)=>"
b="const acceptFile=(candidate:File|null)=>{setErr('');if(!candidate)return;if(!candidate.name.toLowerCase().endsWith('.zip')){setFile(null);setErr('Choose a .zip project archive.');return}if(candidate.size>25*1024*1024){setFile(null);setErr('The ZIP must be 25 MB or smaller.');return}setFile(candidate)};const mark=async(f:F)=>"
assert a in s;s=s.replace(a,b,1)
a='<label className="dropzone" htmlFor="project-archive"><UploadCloud'
b='<label className="dropzone" htmlFor="project-archive" onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();acceptFile(e.dataTransfer.files[0]||null)}}><UploadCloud'
assert a in s;s=s.replace(a,b,1)
a="onChange={e=>setFile(e.target.files?.[0]||null)}"
b="onChange={e=>acceptFile(e.target.files?.[0]||null)}"
assert a in s;s=s.replace(a,b,1)
a='Uploaded files are isolated, inspected as data, then deleted after the scan.'
b='ZIP ≤25 MB · ≤5,000 files · ≤50 MB extracted. Files are isolated, inspected as data, then deleted.'
assert a in s;s=s.replace(a,b,1)
p.write_text(s,encoding='utf-8')
