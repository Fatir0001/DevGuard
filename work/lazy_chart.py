from pathlib import Path
p=Path('frontend/src/App.tsx');s=p.read_text(encoding='utf-8')
old="import{useEffect,useMemo,useState}from'react';"
new="import{lazy,Suspense,useEffect,useMemo,useState}from'react';"
assert old in s;s=s.replace(old,new,1)
old="import{BarChart,Bar,XAxis,YAxis,Tooltip,ResponsiveContainer,CartesianGrid,Cell}from'recharts';"
assert old in s;s=s.replace(old,"const SeverityChart=lazy(()=>import('./SeverityChart'));",1)
old='<ResponsiveContainer width="100%" height={220}><BarChart data={chart} margin={{top:10,right:10,left:-20,bottom:0}}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#253336"/><XAxis dataKey="name" tick={{fill:\'#849493\',fontSize:11}} axisLine={false} tickLine={false}/><YAxis allowDecimals={false} tick={{fill:\'#849493\',fontSize:11}} axisLine={false} tickLine={false}/><Tooltip contentStyle={{background:\'#151e20\',border:\'1px solid #304143\',borderRadius:10,color:\'#e8f0ee\'}}/><Bar dataKey="count" radius={[5,5,0,0]}>{chart.map(item=><Cell key={item.name} fill={({Critical:"#ff5c6c",High:"#ff9b65",Medium:"#e8c866",Low:"#45d6b0",Informational:"#73b8e4"} as Record<string,string>)[item.name]}/>)}</Bar></BarChart></ResponsiveContainer>'
new='<Suspense fallback={<div className="empty-chart">Loading severity chart…</div>}><SeverityChart data={chart}/></Suspense>'
assert old in s;s=s.replace(old,new,1)
p.write_text(s,encoding='utf-8')
