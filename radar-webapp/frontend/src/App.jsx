import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { Play, ShieldAlert, FolderGit2, GitBranch, Terminal, Crosshair, BarChart, List, Network, ChevronDown, ChevronRight } from 'lucide-react';
import * as d3 from 'd3';
import './index.css';

const API_BASE = 'http://127.0.0.1:8000/api';

// ─── D3 Force Graph ───────────────────────────────────────────────────────────
function D3Graph({ nodes, edges }) {
  const svgRef = useRef();
  useEffect(() => {
    if (!nodes?.length || !svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    const width = svgRef.current.parentElement.clientWidth || 900;
    const height = 580;
    svg.attr("width", "100%").attr("height", height);
    const defs = svg.append("defs");
    ['calls','imports','handles'].forEach(k => {
      const col = k==='calls'?'#4a9eda':k==='imports'?'#f39c12':'#2ecc71';
      defs.append("marker").attr("id","arr-"+k).attr("viewBox","0 -4 8 8").attr("refX",14).attr("refY",0)
        .attr("markerWidth",6).attr("markerHeight",6).attr("orient","auto")
        .append("path").attr("d","M0,-4L8,0L0,4").attr("fill",col).attr("opacity",0.7);
    });
    const g = svg.append("g");
    svg.call(d3.zoom().scaleExtent([0.05,8]).on("zoom", e => g.attr("transform", e.transform)));
    const nodesData = nodes.map(d => ({...d}));
    const edgesData = edges.map(d => ({...d}));
    const sim = d3.forceSimulation(nodesData)
      .force("link", d3.forceLink(edgesData).id(d=>d.id).distance(d=>d.dashed?90:55).strength(0.5))
      .force("charge", d3.forceManyBody().strength(-160))
      .force("center", d3.forceCenter(width/2, height/2))
      .force("collide", d3.forceCollide(d=>d.r+5));
    const link = g.append("g").selectAll("line").data(edgesData).enter().append("line")
      .attr("stroke", d=>d.kind==='calls'?'#4a9eda':d.kind==='imports'?'#f39c12':'#2ecc71')
      .attr("stroke-opacity",0.55).attr("stroke-width",d=>d.kind==='handles'?1.4:1.2)
      .attr("stroke-dasharray",d=>d.dashed?'4,3':null)
      .attr("marker-end",d=>'url(#arr-'+d.kind+')');
    const node = g.append("g").selectAll("g").data(nodesData).enter().append("g")
      .call(d3.drag()
        .on("start",(e,d)=>{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;})
        .on("drag",(e,d)=>{d.fx=e.x;d.fy=e.y;})
        .on("end",(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));
    node.append("circle").attr("r",d=>d.r).attr("fill",d=>d.color)
      .attr("stroke",d=>d.kind==='route'?'#fff':'#0f1923').attr("stroke-width",d=>d.kind==='route'?2:1.5);
    node.filter(d=>d.r>=7).append("text").attr("dy",d=>d.r+10).attr("text-anchor","middle")
      .style("font-size","9px").style("fill","#cdd6e0").style("pointer-events","none")
      .text(d=>d.name.length>18?d.name.slice(0,17)+'\u2026':d.name);
    sim.on("tick", ()=>{
      link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
      node.attr("transform",d=>`translate(${d.x},${d.y})`);
    });
  }, [nodes, edges]);
  return (
    <div style={{position:'relative',background:'#0f1923',borderRadius:'10px',overflow:'hidden',border:'1px solid rgba(255,255,255,0.08)'}}>
      <svg ref={svgRef} style={{display:'block'}}></svg>
    </div>
  );
}

// ─── Expandable Blast Radius Stat Card ────────────────────────────────────────
function BlastStatCard({ count, label, color, items, renderItem }) {
  const [open, setOpen] = useState(false);
  const hasItems = items && items.length > 0;

  return (
    <div style={{
      background: 'rgba(255,255,255,0.03)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '10px',
      overflow: 'hidden',
      minWidth: '160px',
      flex: '1',
      cursor: hasItems ? 'pointer' : 'default',
    }}>
      {/* Header / Count row */}
      <div
        onClick={() => hasItems && setOpen(o => !o)}
        style={{padding: '16px', display: 'flex', alignItems: 'flex-start', gap: '10px'}}
      >
        {hasItems && (
          <span style={{color, marginTop: '4px', flexShrink: 0}}>
            {open ? <ChevronDown size={14}/> : <ChevronRight size={14}/>}
          </span>
        )}
        <div>
          <div style={{fontSize: '2rem', fontWeight: '700', color, lineHeight: 1}}>{count}</div>
          <div style={{fontSize: '0.8rem', color: '#94a3b8', marginTop: '5px'}}>{label}</div>
        </div>
      </div>

      {/* Expanded list */}
      {open && hasItems && (
        <div style={{
          borderTop: '1px solid rgba(255,255,255,0.06)',
          maxHeight: '280px',
          overflowY: 'auto',
          background: 'rgba(0,0,0,0.2)',
        }}>
          {items.map((item, i) => (
            <div key={i} style={{
              padding: '8px 16px',
              borderBottom: '1px solid rgba(255,255,255,0.04)',
              fontSize: '0.8rem',
              fontFamily: 'monospace',
              color: '#cdd6e0',
            }}>
              {renderItem ? renderItem(item) : String(item)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
function App() {
  const [repos, setRepos] = useState([]);
  const [engines, setEngines] = useState([]);

  const [repoUrlOrName, setRepoUrlOrName] = useState('');
  const [branch, setBranch] = useState('');
  const [selectedEngines, setSelectedEngines] = useState([]);
  const [targetType, setTargetType] = useState('none');
  const [targetValue, setTargetValue] = useState('');

  const [logs, setLogs] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const logsEndRef = useRef(null);

  useEffect(() => {
    axios.get(`${API_BASE}/repos`).then(res => { setRepos(res.data); if(res.data.length>0) setRepoUrlOrName(res.data[0]); });
    axios.get(`${API_BASE}/engines`).then(res => { setEngines(res.data); setSelectedEngines(res.data.filter(e=>e.default).map(e=>e.name)); });
  }, []);

  useEffect(() => { logsEndRef.current?.scrollIntoView({behavior:'smooth'}); }, [logs]);

  const toggleEngine = n => setSelectedEngines(p => p.includes(n)?p.filter(e=>e!==n):[...p,n]);

  const startScan = async () => {
    if(!repoUrlOrName || selectedEngines.length===0) return;
    setIsScanning(true); setLogs([]); setScanResults(null); setActiveTab('overview');
    try {
      const res = await axios.post(`${API_BASE}/scan`, {
        repo_url_or_name: repoUrlOrName, branch, engines: selectedEngines, target_type: targetType, target_value: targetValue
      });
      const scanId = res.data.scan_id;
      const evtSource = new EventSource(`${API_BASE}/stream/${scanId}`);
      evtSource.onmessage = async e => {
        if(e.data==="READY") {
          const r = await axios.get(`${API_BASE}/results/${scanId}`);
          setScanResults(r.data);
          setIsScanning(false);
          evtSource.close();
        } else {
          setLogs(p => [...p, e.data]);
        }
      };
      evtSource.onerror = () => { evtSource.close(); setIsScanning(false); };
    } catch(err) {
      setLogs(p => [...p, `> ERROR: ${err.message}`]); setIsScanning(false);
    }
  };

  const br = scanResults?.blast_radius;
  const changedItems  = br?.changed  || [];
  const affectedFuncs = (br?.affected || []).filter(i => i.kind === 'function');
  const affectedRoutes= br?.apis || [];
  const features      = br?.features || [];
  const approximate   = (br?.affected || []).filter(i => i.confidence === 'name-only');

  return (
    <div className="app-container">
      <div className="header">
        <h1>Radar Security Center</h1>
        <p className="subtitle">Multi-engine SAST &amp; Blast Radius Analyzer</p>
      </div>

      {/* ── Configuration + Terminal ── */}
      <div className="grid-layout" style={{marginBottom:'24px'}}>
        <div className="glass-panel">
          <h2><ShieldAlert size={20} color="#3b82f6"/> Scan Configuration</h2>

          <div className="form-group">
            <label><FolderGit2 size={14} style={{display:'inline',marginBottom:'-2px'}}/> Repository (Name or GitHub URL)</label>
            <input type="text" list="repo-list" value={repoUrlOrName} onChange={e=>setRepoUrlOrName(e.target.value)}
              placeholder="e.g. koel  or  https://github.com/koel/koel.git"/>
            <datalist id="repo-list">{repos.map(r=><option key={r} value={r}/>)}</datalist>
          </div>

          <div className="form-group">
            <label><GitBranch size={14} style={{display:'inline',marginBottom:'-2px'}}/> Compare Branch (Optional)</label>
            <input type="text" value={branch} onChange={e=>setBranch(e.target.value)}
              placeholder="Leave blank → uses default (main/master)"/>
            <p style={{fontSize:'0.78rem',color:'#64748b',marginTop:'5px'}}>
              Blast Radius will compare this branch against the repo's main branch.
            </p>
          </div>

          <div className="form-group">
            <label><Crosshair size={14} style={{display:'inline',marginBottom:'-2px'}}/> Blast Radius Analysis</label>
            <div style={{display:'flex',gap:'10px'}}>
              <select value={targetType} onChange={e=>{setTargetType(e.target.value);setTargetValue('');}} style={{flex:1}}>
                <option value="none">No Graph — Just Scan</option>
                <option value="diff">Changed Lines vs Main</option>
                <option value="function">Specific Function</option>
                <option value="node">Specific File / Node</option>
              </select>
              {(targetType==='function'||targetType==='node') && (
                <input type="text" value={targetValue} onChange={e=>setTargetValue(e.target.value)}
                  placeholder={targetType==='function'?'e.g. login, verifyToken':'e.g. src/auth.js'}
                  style={{flex:1}}/>
              )}
            </div>
          </div>

          <div className="form-group">
            <label>Scan Engines</label>
            <div className="engine-grid">
              {engines.map(eng => {
                const on = selectedEngines.includes(eng.name);
                return (
                  <div key={eng.name} className={`engine-card ${on?'active':''}`} onClick={()=>toggleEngine(eng.name)}>
                    <div className="engine-checkbox"></div>
                    <div className="engine-info">
                      <h4>{eng.name.charAt(0).toUpperCase()+eng.name.slice(1)}</h4>
                      <p>{eng.description}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <button className="btn-primary" onClick={startScan} disabled={isScanning}
            style={{opacity:isScanning?0.7:1,cursor:isScanning?'wait':'pointer'}}>
            {isScanning ? <>Scanning…</> : <><Play size={18}/> Launch Analysis</>}
          </button>
        </div>

        <div className="glass-panel" style={{display:'flex',flexDirection:'column'}}>
          <h2><Terminal size={20} color="#8b5cf6"/> Live Execution Log</h2>
          <div className="terminal-viewer" style={{flex:1,minHeight:'300px'}}>
            <div className="terminal-header">
              <div className="dot r"></div><div className="dot y"></div><div className="dot g"></div>
            </div>
            {logs.length===0
              ? <div style={{opacity:0.5}}>$ Ready to start.</div>
              : logs.map((l,i)=><div key={i} style={{marginBottom:'4px'}}>{l}</div>)}
            {isScanning && <div style={{marginTop:'10px',animation:'pulse 1s infinite'}}>_</div>}
            <div ref={logsEndRef}/>
          </div>
        </div>
      </div>

      {/* ── Results Dashboard ── */}
      {scanResults && (
        <div className="glass-panel" style={{marginTop:'24px',padding:'0',overflow:'hidden'}}>
          {/* Tab Bar */}
          <div style={{display:'flex',background:'rgba(0,0,0,0.3)',borderBottom:'1px solid rgba(255,255,255,0.05)'}}>
            <button className={`tab-btn ${activeTab==='overview'?'active':''}`} onClick={()=>setActiveTab('overview')}><BarChart size={16}/> Overview</button>
            <button className={`tab-btn ${activeTab==='findings'?'active':''}`} onClick={()=>setActiveTab('findings')}><List size={16}/> Findings <span className="cnt">{scanResults.summary.total}</span></button>
            <button className={`tab-btn ${activeTab==='graph'?'active':''}`} onClick={()=>setActiveTab('graph')}><Network size={16}/> Blast Graph</button>
          </div>

          <div style={{padding:'24px'}}>
            {/* ── OVERVIEW TAB ── */}
            {activeTab==='overview' && (
              <div>
                <p style={{color:'#94a3b8',marginBottom:'24px'}}>
                  Scanned: <b style={{color:'#fff'}}>{scanResults.summary.repo}</b>
                </p>

                {/* Security row */}
                <h3 style={{color:'#e2e8f0',fontSize:'0.85rem',fontWeight:600,textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:'12px'}}>Security Findings</h3>
                <div style={{display:'flex',gap:'15px',flexWrap:'wrap',marginBottom:'32px'}}>
                  <BlastStatCard
                    count={scanResults.summary.total}
                    label="Vulnerabilities"
                    color="#ef4444"
                    items={scanResults.findings}
                    renderItem={f => <><span style={{color: f.severity==='ERROR'?'#ef4444':f.severity==='WARNING'?'#f97316':'#3b82f6'}}>{f.severity}</span> &nbsp;[{f.engine}]&nbsp; {f.path}:{f.line} — {f.message}</>}
                  />
                </div>

                {/* Blast Radius row — only if data exists */}
                {br?.stats && Object.keys(br.stats).length > 0 && (
                  <>
                    <h3 style={{color:'#e2e8f0',fontSize:'0.85rem',fontWeight:600,textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:'12px'}}>Blast Radius Impact</h3>
                    <div style={{display:'flex',gap:'15px',flexWrap:'wrap'}}>
                      <BlastStatCard
                        count={br.stats.changed_nodes || 0}
                        label="Changed Nodes"
                        color="#a78bfa"
                        items={changedItems}
                        renderItem={i => <><span style={{color:'#a78bfa'}}>{i.kind}</span> &nbsp;<b>{i.name}</b> &nbsp;<span style={{color:'#64748b'}}>{i.file}:{i.line}</span></>}
                      />
                      <BlastStatCard
                        count={br.stats.functions_affected || 0}
                        label="Functions Affected"
                        color="#f97316"
                        items={affectedFuncs}
                        renderItem={i => <><b>{i.name}</b> &nbsp;<span style={{color:'#64748b'}}>{i.file}:{i.line}</span></>}
                      />
                      <BlastStatCard
                        count={br.stats.apis_affected || 0}
                        label="APIs Exposed"
                        color="#ef4444"
                        items={affectedRoutes}
                        renderItem={a => <><span style={{color:'#93c5fd'}}>⚡ {a.route}</span> &nbsp;<span style={{color:'#64748b'}}>{a.file}</span></>}
                      />
                      <BlastStatCard
                        count={br.stats.features_affected || 0}
                        label="Features Touched"
                        color="#22c55e"
                        items={features}
                        renderItem={f => String(f)}
                      />
                      <BlastStatCard
                        count={br.stats.approximate || 0}
                        label="Approximate"
                        color="#94a3b8"
                        items={approximate}
                        renderItem={i => <><b>{i.name}</b> &nbsp;<span style={{color:'#64748b'}}>{i.file}</span></>}
                      />
                    </div>
                  </>
                )}
              </div>
            )}

            {/* ── FINDINGS TAB ── */}
            {activeTab==='findings' && (
              <div style={{overflowX:'auto',background:'rgba(0,0,0,0.2)',borderRadius:'10px'}}>
                <table style={{width:'100%',borderCollapse:'collapse',fontSize:'0.9rem'}}>
                  <thead>
                    <tr style={{borderBottom:'1px solid rgba(255,255,255,0.1)'}}>
                      {['Severity','Engine','Rule','File:Line','Message'].map(h=>(
                        <th key={h} style={{padding:'12px',textAlign:'left',color:'#94a3b8'}}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.findings.map((f,i)=>(
                      <tr key={i} style={{borderBottom:'1px solid rgba(255,255,255,0.05)'}}>
                        <td style={{padding:'12px',color:f.severity==='ERROR'?'#ef4444':f.severity==='WARNING'?'#f97316':'#3b82f6'}}>{f.severity}</td>
                        <td style={{padding:'12px',opacity:0.8}}>{f.engine}</td>
                        <td style={{padding:'12px',opacity:0.8,fontFamily:'monospace',fontSize:'0.8rem'}}>{f.rule}</td>
                        <td style={{padding:'12px',fontFamily:'monospace',fontSize:'0.8rem'}}>{f.path}:{f.line}</td>
                        <td style={{padding:'12px',opacity:0.9}}>{f.message}</td>
                      </tr>
                    ))}
                    {!scanResults.findings.length && (
                      <tr><td colSpan="5" style={{padding:'30px',textAlign:'center',color:'#22c55e'}}>✅ No vulnerabilities found!</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* ── GRAPH TAB ── */}
            {activeTab==='graph' && (
              <div>
                <div style={{display:'flex',gap:'20px',marginBottom:'16px',color:'#94a3b8',fontSize:'0.9rem'}}>
                  <span>Nodes: <b style={{color:'#fff'}}>{br?.nodes?.length||0}</b></span>
                  <span>Edges: <b style={{color:'#fff'}}>{br?.edges?.length||0}</b></span>
                  <span style={{fontSize:'0.8rem',opacity:0.6}}>Drag to move · Scroll to zoom</span>
                </div>
                {br?.nodes?.length>0
                  ? <D3Graph nodes={br.nodes} edges={br.edges}/>
                  : <div style={{textAlign:'center',padding:'60px',color:'#94a3b8',background:'rgba(0,0,0,0.2)',borderRadius:'10px'}}>
                      No graph data. Select "Changed Lines vs Main" or "Specific Function" to generate the impact graph.
                    </div>
                }
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
