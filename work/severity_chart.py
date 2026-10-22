from pathlib import Path
p=Path('frontend/src/App.tsx');s=p.read_text(encoding='utf-8')
old="import{BarChart,Bar,XAxis,YAxis,Tooltip,ResponsiveContainer,CartesianGrid}from'recharts';"
new="import{BarChart,Bar,XAxis,YAxis,Tooltip,ResponsiveContainer,CartesianGrid,Cell}from'recharts';"
assert old in s;s=s.replace(old,new,1)
old='<Bar dataKey="count" fill="#39ff88" radius={[5,5,0,0]}/>'
new='<Bar dataKey="count" radius={[5,5,0,0]}>{chart.map(item=><Cell key={item.name} fill={({Critical:"#ff5c6c",High:"#ff9b65",Medium:"#e8c866",Low:"#45d6b0",Informational:"#73b8e4"} as Record<string,string>)[item.name]}/>)}</Bar>'
assert old in s;s=s.replace(old,new,1)
p.write_text(s,encoding='utf-8')
