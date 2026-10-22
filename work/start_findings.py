from pathlib import Path
p=Path('frontend/src/App.tsx');s=p.read_text(encoding='utf-8')
a="const s=await req('/scans/'+x.scan_id);setSelected(s);setPage('Scan progress');await refresh()"
b="const s=await req('/scans/'+x.scan_id);setSelected(s);if(s.status==='completed')setFindings((await req(`/scans/${s.id}/findings`)).items);setPage('Scan progress');await refresh()"
assert a in s;s=s.replace(a,b,1);p.write_text(s,encoding='utf-8')
