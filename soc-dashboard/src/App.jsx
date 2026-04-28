import { useState, useEffect, useRef, useCallback } from "react";
import { io } from "socket.io-client";

// ═══════════════════════════════════════════════════════════════════
//  DETECTION RULES — aligned with Table 3.1 (Chapter 3)
// ═══════════════════════════════════════════════════════════════════
const RULES = {
  "Port Scan":                  { id:"RULE-001", mitre:"T1046",     layer:"Statistical", sev:"HIGH",     conf:[86,96] },
  "SYN Flood / DDoS":           { id:"RULE-002", mitre:"T1498",     layer:"Statistical", sev:"CRITICAL", conf:[90,99] },
  "SSH Brute Force":            { id:"RULE-003", mitre:"T1110",     layer:"Signature",   sev:"CRITICAL", conf:[88,98] },
  "RDP Brute Force":            { id:"RULE-004", mitre:"T1110.001", layer:"Signature",   sev:"CRITICAL", conf:[88,98] },
  "FTP Brute Force":            { id:"RULE-005", mitre:"T1110",     layer:"Signature",   sev:"HIGH",     conf:[85,95] },
  "Telnet Brute Force":         { id:"RULE-006", mitre:"T1110",     layer:"Signature",   sev:"HIGH",     conf:[85,95] },
  "C2 Beacon Detected":         { id:"RULE-007", mitre:"T1071",     layer:"Statistical", sev:"CRITICAL", conf:[80,92] },
  "DNS Tunneling":              { id:"RULE-008", mitre:"T1071.004", layer:"Statistical", sev:"HIGH",     conf:[76,90] },
  "ARP Spoofing / MITM":        { id:"RULE-009", mitre:"T1557.002", layer:"Signature",   sev:"CRITICAL", conf:[92,99] },
  "Lateral Movement":           { id:"RULE-010", mitre:"T1021",     layer:"Statistical", sev:"CRITICAL", conf:[82,94] },
  "Data Exfiltration":          { id:"RULE-011", mitre:"T1041",     layer:"Statistical", sev:"CRITICAL", conf:[80,92] },
  "ICMP Flood":                 { id:"RULE-012", mitre:"T1498.001", layer:"Statistical", sev:"HIGH",     conf:[88,97] },
  "Suspicious Port Connection": { id:"RULE-013", mitre:"T1571",     layer:"Signature",   sev:"CRITICAL", conf:[90,99] },
  "SQL Injection (HTTP)":       { id:"RULE-014", mitre:"T1190",     layer:"Signature",   sev:"CRITICAL", conf:[88,97] },
  "Directory Traversal":        { id:"RULE-015", mitre:"T1083",     layer:"Signature",   sev:"HIGH",     conf:[86,95] },
};

const THREAT_TYPES = Object.keys(RULES);

const SOURCES = [
  "192.168.1.45","10.0.0.23","172.16.5.89","203.0.113.12",
  "198.51.100.7","192.0.2.55","10.10.5.200","172.31.0.44",
];

const DESTINATIONS = [
  "10.0.0.1","192.168.0.1","172.16.0.254","10.255.255.1",
  "203.0.113.50","198.51.100.1","192.168.100.1","10.0.0.254",
];

const LOG_TEMPLATES = {
  "Port Scan":                  (s,d)=>`[NET] ${s} scanned ${ri(16,55)} unique ports on ${d} within 60s — threshold exceeded`,
  "SYN Flood / DDoS":           (s,d)=>`[NET] SYN flood: ${ri(101,950)} SYN/sec from ${s} to ${d} — RULE-002 threshold breached`,
  "SSH Brute Force":            (s,d)=>`[AUTH] ${ri(11,40)} failed SSH auth attempts: ${s} to ${d}:22 in 60s`,
  "RDP Brute Force":            (s,d)=>`[AUTH] ${ri(11,35)} failed RDP attempts: ${s} to ${d}:3389 within 60s`,
  "FTP Brute Force":            (s,d)=>`[AUTH] ${ri(11,30)} failed FTP login attempts from ${s} to ${d}:21`,
  "Telnet Brute Force":         (s,d)=>`[AUTH] Repeated Telnet connection attempts: ${s} to ${d}:23 (${ri(11,25)} attempts)`,
  "C2 Beacon Detected":         (s,d)=>`[NET] Periodic beaconing: ${s} to ${d} every ~${ri(30,65)}s (std_dev=${(Math.random()*2+0.3).toFixed(2)}s)`,
  "DNS Tunneling":              (s,d)=>`[DNS] Avg DNS query payload ${ri(101,320)} bytes from ${s} — possible tunneling to ${d}`,
  "ARP Spoofing / MITM":        (s,d)=>`[ARP] IP ${d} MAC address changed unexpectedly — source: ${s} — possible MITM`,
  "Lateral Movement":           (s,d)=>`[NET] Internal host ${s} contacted ${ri(11,28)} internal IPs including ${d} in 60s`,
  "Data Exfiltration":          (s,d)=>`[NET] ${ri(51,280)}MB outbound from ${s} to ${d} within 60s — exceeds 50MB baseline`,
  "ICMP Flood":                 (s,d)=>`[NET] ICMP flood: ${ri(51,600)} packets/sec from ${s} targeting ${d}`,
  "Suspicious Port Connection": (s,d)=>`[NET] ${s} connected to ${d}:${[4444,1337,31337,8888,9999][ri(0,4)]} (known C2 port)`,
  "SQL Injection (HTTP)":       (s,d)=>`[HTTP] SQL pattern in request from ${s} to ${d}/api — payload: UNION SELECT * FROM users`,
  "Directory Traversal":        (s,d)=>`[HTTP] Traversal attempt from ${s} to ${d} — path: /../../../etc/passwd`,
};

const ri   = (a,b) => Math.floor(Math.random()*(b-a+1))+a;
const rf   = (a,b) => +(Math.random()*(b-a)+a).toFixed(1);
const pick = arr   => arr[Math.floor(Math.random()*arr.length)];

function mkAlert() {
  const type = pick(THREAT_TYPES);
  const rule = RULES[type];
  const src  = pick(SOURCES);
  const dst  = pick(DESTINATIONS);
  return {
    id:         Date.now()+Math.random(),
    timestamp:  new Date().toISOString().replace("T"," ").slice(0,19),
    type, src, dst,
    severity:   rule.sev,
    confidence: rf(rule.conf[0], rule.conf[1]),
    ruleId:     rule.id,
    mitre:      rule.mitre,
    layer:      rule.layer,
    log:        LOG_TEMPLATES[type](src,dst),
    status:     "NEW",
    real:       false,
  };
}

// ═══════════════════════════════════════════════════════════════════
//  ARIA — OpenRouter API
//  Replace YOUR_OPENROUTER_API_KEY_HERE with your key from
//  https://openrouter.ai/keys  OR  set VITE_OPENROUTER_API_KEY in .env
// ═══════════════════════════════════════════════════════════════════
const OPENROUTER_KEY = import.meta.env.VITE_OPENROUTER_API_KEY;

async function callARIA(messages) {
  const sys = `You are ARIA (Automated Response Intelligence Analyst), the embedded AI analyst in the SOC·NEXUS Hybrid Network-Based IDS dashboard — a final year BSc Cybersecurity project by Fatima Salisu (U22CYS1117) at AFIT Kaduna.

DETECTION ENGINE — Two layers:
• Signature Layer (8 rules): RULE-003 SSH Brute Force T1110 CRITICAL, RULE-004 RDP Brute Force T1110.001 CRITICAL, RULE-005 FTP Brute Force T1110 HIGH, RULE-006 Telnet Brute Force T1110 HIGH, RULE-009 ARP Spoofing T1557.002 CRITICAL, RULE-013 Suspicious Port T1571 CRITICAL, RULE-014 SQL Injection T1190 CRITICAL, RULE-015 Directory Traversal T1083 HIGH
• Statistical Layer (7 rules): RULE-001 Port Scan T1046 HIGH (>15 ports/min), RULE-002 SYN Flood T1498 CRITICAL (>100 SYN/sec), RULE-007 C2 Beaconing T1071 CRITICAL (std_dev<5s), RULE-008 DNS Tunneling T1071.004 HIGH (avg payload>100B), RULE-010 Lateral Movement T1021 CRITICAL (>10 IPs/min), RULE-011 Data Exfiltration T1041 CRITICAL (>50MB/min), RULE-012 ICMP Flood T1498.001 HIGH (>50 ICMP/sec)

EVALUATION RESULTS (Chapter 4): 94.8% detection rate, 4.4% FPR, 142ms avg latency. No ML training used.
KEY REFS: Khraisat et al. 2020 (hybrid outperforms single-method), Sommer & Paxson 2021 (rule-based reliable in ops), Brown et al. 2023 (LLM improves analyst efficiency 40-60%).

ROLE: Decision support ONLY. Recommend analyst verification before acting. Be concise and reference MITRE ATT&CK.`;

  const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${OPENROUTER_KEY}`,
      "HTTP-Referer":  "https://soc-nexus-afit.vercel.app",
      "X-Title":       "SOC NEXUS - AFIT Kaduna",
    },
    body: JSON.stringify({
      model: "openrouter/free",
      messages: [
        { role:"system", content:sys },
        ...messages.map(m=>({ role:m.role, content:m.content })),
      ],
    }),
  });
  const data = await res.json();
  if(data.error) return `⚠ ARIA Error: ${data.error.message || "Check your API key in the .env file or replace YOUR_OPENROUTER_API_KEY_HERE in App.jsx"}`;
  return data.choices?.[0]?.message?.content || "No response received from ARIA.";
}

// ═══════════════════════════════════════════════════════════════════
//  DESIGN TOKENS
// ═══════════════════════════════════════════════════════════════════
const C = {
  bg:      "#F0F4F8",
  surface: "#FFFFFF",
  navy:    "#1A2E4A",
  navyLt:  "#EEF2F7",
  teal:    "#0D9488",
  tealLt:  "#CCFBF1",
  blue:    "#1D6FA4",
  blueLt:  "#DBEAFE",
  purple:  "#7C3AED",
  purpLt:  "#EDE9FE",
  crit:    "#DC2626",
  critLt:  "#FEE2E2",
  high:    "#D97706",
  highLt:  "#FEF3C7",
  med:     "#0891B2",
  medLt:   "#CFFAFE",
  low:     "#16A34A",
  lowLt:   "#DCFCE7",
  text:    "#1A2E4A",
  muted:   "#64748B",
  dim:     "#94A3B8",
  border:  "#E2E8F0",
};

const SEV = {
  CRITICAL:{ fg:C.crit,   bg:C.critLt  },
  HIGH:    { fg:C.high,   bg:C.highLt  },
  MEDIUM:  { fg:C.med,    bg:C.medLt   },
  LOW:     { fg:C.low,    bg:C.lowLt   },
};

// ═══════════════════════════════════════════════════════════════════
//  COMPONENTS
// ═══════════════════════════════════════════════════════════════════
function Chip({ label, fg, bg, size=10 }) {
  return (
    <span style={{
      background:bg, color:fg, fontSize:size,
      padding:"2px 9px", borderRadius:20,
      fontWeight:700, letterSpacing:.4,
      fontFamily:"'JetBrains Mono',monospace",
      whiteSpace:"nowrap", display:"inline-flex", alignItems:"center",
    }}>{label}</span>
  );
}

function SevChip({ sev }) {
  const m=SEV[sev]||SEV.LOW;
  return <Chip label={sev} fg={m.fg} bg={m.bg}/>;
}

function LayerChip({ layer }) {
  return <Chip label={layer}
    fg={layer==="Signature"?C.blue:C.purple}
    bg={layer==="Signature"?C.blueLt:C.purpLt}/>;
}

function Panel({ children, style }) {
  return (
    <div style={{
      background:C.surface,
      borderRadius:14,
      border:`1px solid ${C.border}`,
      boxShadow:"0 2px 14px rgba(26,46,74,.07)",
      overflow:"hidden",
      ...style,
    }}>{children}</div>
  );
}

function PanelHead({ icon, title, right }) {
  return (
    <div style={{
      display:"flex", alignItems:"center", gap:8,
      padding:"13px 18px 11px",
      borderBottom:`1px solid ${C.border}`,
    }}>
      <span style={{ fontSize:15 }}>{icon}</span>
      <span style={{
        fontSize:10, fontWeight:700, letterSpacing:1.8,
        color:C.muted, textTransform:"uppercase",
        fontFamily:"'JetBrains Mono',monospace",
      }}>{title}</span>
      {right && <div style={{ marginLeft:"auto" }}>{right}</div>}
    </div>
  );
}

function KpiCard({ icon, label, value, sub, accent }) {
  return (
    <Panel style={{ borderTop:`3px solid ${accent}` }}>
      <div style={{ padding:"16px 20px" }}>
        <div style={{ display:"flex", alignItems:"center", gap:7, marginBottom:6 }}>
          <span style={{ fontSize:18 }}>{icon}</span>
          <span style={{ fontSize:9, color:C.muted, letterSpacing:1.8, textTransform:"uppercase", fontWeight:700 }}>{label}</span>
        </div>
        <div style={{ fontSize:30, fontWeight:800, color:accent, fontFamily:"'JetBrains Mono',monospace", lineHeight:1 }}>{value}</div>
        {sub && <div style={{ fontSize:10, color:C.dim, marginTop:3 }}>{sub}</div>}
      </div>
    </Panel>
  );
}

function Ring({ pct, color, label }) {
  const r=28, cx=36, cy=36, circ=2*Math.PI*r;
  const dash=(Math.min(pct,100)/100)*circ;
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:5 }}>
      <svg width={72} height={72} viewBox="0 0 72 72">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.bg} strokeWidth={7}/>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={7}
          strokeDasharray={`${dash} ${circ-dash}`} strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition:"stroke-dasharray .9s ease" }}/>
        <text x={cx} y={cy+5} textAnchor="middle" fill={color}
          fontSize={12} fontWeight="800"
          fontFamily="'JetBrains Mono',monospace">{Math.round(pct)}%</text>
      </svg>
      <span style={{ fontSize:9, color:C.muted, letterSpacing:1.5, textTransform:"uppercase", fontWeight:600 }}>{label}</span>
    </div>
  );
}

function Bar({ label, value, max, color }) {
  return (
    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
      <div style={{ width:155, fontSize:10, color:C.muted, textAlign:"right", flexShrink:0, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{label}</div>
      <div style={{ flex:1, height:9, background:C.bg, borderRadius:5, overflow:"hidden" }}>
        <div style={{ width:max>0?`${(value/max)*100}%`:"0%", height:"100%", background:color, borderRadius:5, transition:"width .5s ease", minWidth:value>0?4:0 }}/>
      </div>
      <div style={{ width:26, fontSize:10, color, fontWeight:700, fontFamily:"'JetBrains Mono',monospace", textAlign:"right" }}>{value}</div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
//  APP
// ═══════════════════════════════════════════════════════════════════
export default function App() {
  const [tab,          setTab]         = useState("dashboard");
  const [alerts,       setAlerts]      = useState(()=>Array.from({length:14},mkAlert));
  const [selected,     setSelected]    = useState(null);
  const [paused,       setPaused]      = useState(false);
  const [sevFilter,    setSevFilter]   = useState("ALL");
  const [layerFilter,  setLayerFilter] = useState("ALL");
  const [threatCounts, setThreatCounts]= useState({});
  const [layerCounts,  setLayerCounts] = useState({Signature:0,Statistical:0});
  const [metrics,      setMetrics]     = useState({total:0,critical:0,mitigated:0,fp:0});
  const [dr,           setDr]          = useState(94.8);
  const [fpr,          setFpr]         = useState(4.4);
  const [latency,      setLatency]     = useState(142);
  const [agentLive,    setAgentLive]   = useState(false);
  const [chat,         setChat]        = useState([{
    role:"assistant",
    content:"**ARIA online.** I am your hybrid SOC analyst assistant.\n\nThis dashboard implements a two-layer hybrid detection engine:\n\n• **Signature Layer** — 8 deterministic threshold rules\n• **Statistical Layer** — 7 mathematical behavioral analysis rules\n\nCovering 15 threat categories and 10 attack types. Ask me about any alert, MITRE technique, detection rule, or incident response procedure.",
  }]);
  const [chatInput,    setChatInput]   = useState("");
  const [chatLoading,  setChatLoading] = useState(false);
  const [logFile,      setLogFile]     = useState(null);
  const [logContent,   setLogContent]  = useState(null);
  const chatEnd  = useRef(null);
  const itvRef   = useRef(null);

  // ── Simulation ─────────────────────────────────────────────────
  useEffect(()=>{
    if(paused) return;
    itvRef.current = setInterval(()=>{
      const a = mkAlert();
      setAlerts(p=>[a,...p.slice(0,49)]);
      setThreatCounts(p=>({...p,[a.type]:(p[a.type]||0)+1}));
      setLayerCounts(p=>({...p,[a.layer]:(p[a.layer]||0)+1}));
      setMetrics(p=>({
        total:    p.total+1,
        critical: p.critical+(a.severity==="CRITICAL"?1:0),
        mitigated:p.mitigated+(Math.random()>.42?1:0),
        fp:       p.fp+(Math.random()<.044?1:0),
      }));
      setDr(d=>Math.min(99,Math.max(90,d+(Math.random()-.5)*.15)));
      setFpr(f=>Math.min(9,Math.max(2,f+(Math.random()-.5)*.08)));
      setLatency(l=>Math.min(380,Math.max(80,l+ri(-12,12))));
    },2800);
    return()=>clearInterval(itvRef.current);
  },[paused]);

  // ── Connect to real Python agent ───────────────────────────────
  useEffect(() => {
    const socket = io("http://localhost:5000");

    socket.on("connect", () => {
      setAgentLive(true);
      console.log("Agent connected");
    });

    socket.on("disconnect", () => {
      setAgentLive(false);
    });

    socket.on("real_alert", (a) => {
      // Real packet from network — add to top of alerts
      const realAlert = {
        ...a,
        type: a.type,
        src:  a.src,
        dst:  a.dst,
        sev:  a.severity,   // backend sends "severity", frontend uses "sev"
        conf: a.confidence, // backend sends "confidence", frontend uses "conf"
        real: true,
      };
      setAlerts(prev => [realAlert, ...prev.slice(0, 49)]);
      setThreatCounts(prev => ({ ...prev, [a.type]: (prev[a.type] || 0) + 1 }));
      setLayerCounts(prev => ({ ...prev, [a.layer]: (prev[a.layer] || 0) + 1 }));
      setMetrics(prev => ({
        total:    prev.total + 1,
        critical: prev.critical + (a.severity === "CRITICAL" ? 1 : 0),
        mitigated:prev.mitigated,
        fp:       prev.fp,
      }));
    });

  return () => socket.disconnect();
}, []);

  // ── Chat ───────────────────────────────────────────────────────
  const sendChat = useCallback(async()=>{
    if(!chatInput.trim()||chatLoading) return;
    const msg={role:"user",content:chatInput};
    const next=[...chat,msg];
    setChat(next); setChatInput(""); setChatLoading(true);
    try{
      const r=await callARIA(next);
      setChat(p=>[...p,{role:"assistant",content:r}]);
    }catch(e){
      setChat(p=>[...p,{role:"assistant",content:`⚠ ARIA connection failed: ${e.message}. Check your VITE_OPENROUTER_API_KEY.`}]);
    }
    setChatLoading(false);
  },[chat,chatInput,chatLoading]);

  // ── Alert analyze ──────────────────────────────────────────────
  const analyzeAlert = useCallback(async(a)=>{
    setTab("aria");
    const msg={role:"user",content:`Analyze this network alert:\n\n**Type:** ${a.type}\n**Rule:** ${a.ruleId}\n**Severity:** ${a.severity}\n**Src:** ${a.src} → **Dst:** ${a.dst}\n**Layer:** ${a.layer}\n**MITRE:** ${a.mitre}\n**Confidence:** ${a.confidence}%\n**Log:** ${a.log}\n\nProvide: (1) threat assessment and kill chain stage, (2) immediate response actions, (3) false positive assessment, (4) MITRE context`};
    const next=[...chat,msg];
    setChat(next); setChatLoading(true);
    try{
      const r=await callARIA(next);
      setChat(p=>[...p,{role:"assistant",content:r}]);
    }catch{ setChat(p=>[...p,{role:"assistant",content:"⚠ ARIA analysis failed."}]); }
    setChatLoading(false);
  },[chat]);

  // ── Log upload ─────────────────────────────────────────────────
  const uploadLog = useCallback((e)=>{
    const f=e.target.files[0]; if(!f) return;
    setLogFile(f.name);
    const r=new FileReader();
    r.onload=ev=>setLogContent(ev.target.result);
    r.readAsText(f);
  },[]);

  const analyzeLog = useCallback(async()=>{
    if(!logContent) return;
    setTab("aria");
    const msg={role:"user",content:`Analyze this security log file: "${logFile}"\n\nIdentify threats, which RULE-001–015 would trigger, severity, and recommended response.\n\nLog content:\n\`\`\`\n${logContent.slice(0,3000)}\n\`\`\``};
    const next=[...chat,msg];
    setChat(next); setChatLoading(true);
    try{
      const r=await callARIA(next);
      setChat(p=>[...p,{role:"assistant",content:r}]);
    }catch{ setChat(p=>[...p,{role:"assistant",content:"⚠ Log analysis failed."}]); }
    setChatLoading(false);
  },[logContent,logFile,chat]);

  const filtered = alerts.filter(a=>(sevFilter==="ALL"||a.severity===sevFilter)&&(layerFilter==="ALL"||a.layer===layerFilter));
  const layerTotal = (layerCounts.Signature||0)+(layerCounts.Statistical||0);

  // ── Button styles ──────────────────────────────────────────────
  const navStyle = active=>({
    padding:"8px 16px",
    background:active?C.navy:"transparent",
    color:active?"#fff":C.muted,
    border:"none", borderRadius:8,
    cursor:"pointer", fontSize:12, fontWeight:600,
    letterSpacing:.4, transition:"all .2s",
    display:"flex", alignItems:"center", gap:6,
    fontFamily:"inherit",
  });

  const fBtn = (active,color)=>({
    padding:"4px 12px",
    background:active?color+"18":"transparent",
    color:active?color:C.dim,
    border:`1px solid ${active?color+"55":C.border}`,
    borderRadius:20, cursor:"pointer",
    fontSize:10, fontWeight:600, letterSpacing:.4,
    transition:"all .15s", fontFamily:"inherit",
  });

  const alertRow = (a,sel)=>({
    display:"flex", alignItems:"flex-start", gap:10,
    padding:"10px 14px", borderRadius:10,
    cursor:"pointer", marginBottom:4,
    background:sel?C.navyLt:"transparent",
    borderLeft:`3px solid ${SEV[a.severity]?.fg||C.low}`,
    transition:"background .15s",
  });

  // ═══════════════════════════════════════════════════════════════
  return (
    <div style={{ minHeight:"100vh", background:C.bg, color:C.text, fontFamily:"'DM Sans','Segoe UI',system-ui,sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700;9..40,800&family=JetBrains+Mono:wght@400;600;700&display=swap');
        @keyframes fadeUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
        @keyframes pulse  { 0%,100%{opacity:1} 50%{opacity:.35} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::-webkit-scrollbar{width:5px;height:5px}
        ::-webkit-scrollbar-track{background:${C.bg}}
        ::-webkit-scrollbar-thumb{background:${C.border};border-radius:3px}
        .arow:hover{background:${C.navyLt}!important}
        .nbtn:hover{background:${C.navyLt}!important;color:${C.navy}!important}
        .pchip:hover{background:${C.navyLt}!important;color:${C.navy}!important}
      `}</style>

      {/* ══ HEADER ════════════════════════════════════════════════ */}
      <header style={{
        background:C.surface, borderBottom:`1px solid ${C.border}`,
        padding:"0 24px", display:"flex", alignItems:"center",
        height:58, gap:10, position:"sticky", top:0, zIndex:100,
        boxShadow:"0 1px 10px rgba(26,46,74,.07)",
      }}>
        {/* Brand */}
        <div style={{ display:"flex", alignItems:"center", gap:10, marginRight:10 }}>
          <div style={{
            width:36, height:36,
            background:`linear-gradient(135deg,${C.navy},${C.teal})`,
            borderRadius:10, display:"flex", alignItems:"center",
            justifyContent:"center", fontSize:18,
            boxShadow:`0 4px 12px ${C.navy}33`,
          }}>🛡</div>
          <div>
            <div style={{ fontSize:15, fontWeight:800, color:C.navy, letterSpacing:1.2 }}>SOC·NEXUS</div>
            <div style={{ fontSize:8, color:C.dim, letterSpacing:2, marginTop:-1 }}>HYBRID NIDS · AFIT KADUNA</div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ display:"flex", gap:3 }}>
          {[
            {k:"dashboard",i:"⬡",l:"Dashboard"},
            {k:"alerts",   i:"⚠",l:"Alerts"},
            {k:"rules",    i:"≡",l:"Rules"},
            {k:"logs",     i:"📁",l:"Logs"},
            {k:"aria",     i:"✦",l:"ARIA AI"},
          ].map(n=>(
            <button key={n.k} className="nbtn" style={navStyle(tab===n.k)} onClick={()=>setTab(n.k)}>
              <span>{n.i}</span>{n.l}
            </button>
          ))}
        </nav>

        {/* Status */}
        <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:14 }}>
          <div style={{ display:"flex", alignItems:"center", gap:5, fontSize:10, color:agentLive?C.teal:C.dim }}>
            <div style={{ width:6, height:6, borderRadius:"50%", background:agentLive?C.teal:C.dim, animation:"pulse 2s ease-in-out infinite" }}/>
            {agentLive?"AGENT LIVE":"AGENT OFFLINE"}
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:5, fontSize:10, color:paused?C.high:C.teal }}>
            <div style={{ width:6, height:6, borderRadius:"50%", background:paused?C.high:C.teal, animation:paused?"none":"pulse 2s ease-in-out infinite" }}/>
            {paused?"PAUSED":"LIVE SIM"}
          </div>
          <button onClick={()=>setPaused(p=>!p)} style={{
            background:paused?C.highLt:C.tealLt, color:paused?C.high:C.teal,
            border:`1px solid ${paused?C.high+"44":C.teal+"44"}`,
            padding:"5px 14px", borderRadius:20,
            cursor:"pointer", fontSize:10, fontWeight:700, fontFamily:"inherit",
          }}>{paused?"▶ Resume":"⏸ Pause"}</button>
          <span style={{ fontSize:10, color:C.dim, fontFamily:"'JetBrains Mono',monospace" }}>
            {new Date().toLocaleTimeString()}
          </span>
        </div>
      </header>

      {/* ══ CONTENT ═══════════════════════════════════════════════ */}
      <main style={{ padding:"20px 24px", maxWidth:1440, margin:"0 auto" }}>

        {/* ── DASHBOARD ──────────────────────────────────────────── */}
        {tab==="dashboard" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16, animation:"fadeUp .4s ease" }}>

            {/* KPIs */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12 }}>
              <KpiCard icon="📡" label="Total Events"   value={metrics.total}    sub="session total"  accent={C.blue}/>
              <KpiCard icon="🔴" label="Critical"        value={metrics.critical} sub="active threats" accent={C.crit}/>
              <KpiCard icon="✅" label="Mitigated"       value={metrics.mitigated} sub="auto-resolved" accent={C.teal}/>
              <KpiCard icon="🟡" label="False Positives"
                value={metrics.fp}
                sub={`${metrics.total>0?((metrics.fp/metrics.total)*100).toFixed(1):0}% rate`}
                accent={C.high}/>
              <KpiCard icon="⚡" label="Latency" value={`${latency}ms`} sub="avg detection" accent={C.purple}/>
            </div>

            {/* Charts row */}
            <div style={{ display:"grid", gridTemplateColumns:"1.15fr .85fr", gap:16 }}>

              {/* Threat distribution */}
              <Panel>
                <PanelHead icon="📊" title="Threat Distribution"
                  right={<span style={{ fontSize:9, color:C.dim, fontFamily:"'JetBrains Mono',monospace" }}>{Object.keys(threatCounts).length} types</span>}/>
                <div style={{ padding:"14px 18px" }}>
                  {Object.keys(threatCounts).length===0
                    ? <div style={{ color:C.dim, textAlign:"center", padding:28, fontSize:12 }}>Awaiting events…</div>
                    : Object.entries(threatCounts)
                        .sort(([,a],[,b])=>b-a).slice(0,8)
                        .map(([k,v])=>(
                          <Bar key={k} label={k} value={v}
                            max={Math.max(...Object.values(threatCounts))}
                            color={RULES[k]?.layer==="Signature"?C.blue:C.purple}/>
                        ))
                  }
                </div>
              </Panel>

              {/* Performance */}
              <Panel>
                <PanelHead icon="◈" title="Detection Performance"/>
                <div style={{ padding:"14px 18px" }}>
                  <div style={{ display:"flex", justifyContent:"space-around", marginBottom:16 }}>
                    <Ring pct={dr}               color={C.teal}   label="Detection"/>
                    <Ring pct={100-fpr*8}        color={C.blue}   label="Precision"/>
                    <Ring pct={(dr+100-fpr*8)/2} color={C.purple} label="F1 Score"/>
                    <Ring pct={94.8}             color={C.high}   label="Coverage"/>
                  </div>

                  <div style={{ borderTop:`1px solid ${C.border}`, paddingTop:12 }}>
                    <div style={{ fontSize:9, color:C.muted, letterSpacing:1.8, textTransform:"uppercase", fontWeight:700, marginBottom:8 }}>Layer Breakdown</div>
                    {[
                      {key:"Signature",   color:C.blue,   label:"Signature Layer",   rules:"8 rules"},
                      {key:"Statistical", color:C.purple, label:"Statistical Layer",  rules:"7 rules"},
                    ].map(l=>{
                      const cnt=layerCounts[l.key]||0;
                      const pct=layerTotal>0?(cnt/layerTotal)*100:0;
                      return (
                        <div key={l.key} style={{ marginBottom:9 }}>
                          <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, marginBottom:3 }}>
                            <span style={{ color:l.color, fontWeight:600 }}>{l.label} <span style={{ color:C.dim }}>({l.rules})</span></span>
                            <span style={{ color:l.color, fontFamily:"'JetBrains Mono',monospace" }}>{cnt}</span>
                          </div>
                          <div style={{ height:7, background:C.bg, borderRadius:4, overflow:"hidden" }}>
                            <div style={{ width:`${pct}%`, height:"100%", background:l.color, borderRadius:4, transition:"width .6s ease" }}/>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </Panel>
            </div>

            {/* Live stream */}
            <Panel>
              <PanelHead icon="⚡" title="Live Alert Stream"
                right={<span style={{ fontSize:9, color:C.dim }}>{alerts.length} buffered</span>}/>
              <div style={{ maxHeight:256, overflowY:"auto", padding:"8px 14px" }}>
                {alerts.slice(0,8).map(a=>(
                  <div key={a.id} className="arow"
                    style={alertRow(a, selected?.id===a.id)}
                    onClick={()=>{ setSelected(a); setTab("alerts"); }}>
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:3, flexWrap:"wrap" }}>
                        <SevChip sev={a.severity}/><LayerChip layer={a.layer}/>
                        <span style={{ fontSize:12, fontWeight:700, color:C.navy }}>{a.type}</span>
                        <span style={{ fontSize:9, color:C.dim, marginLeft:"auto", fontFamily:"'JetBrains Mono',monospace" }}>{a.timestamp}</span>
                      </div>
                      <div style={{ fontSize:10, color:C.muted, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {a.ruleId} · {a.mitre} · {a.src} → {a.dst} · {a.confidence}% conf.
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        )}

        {/* ── ALERTS ─────────────────────────────────────────────── */}
        {tab==="alerts" && (
          <div style={{ animation:"fadeUp .4s ease" }}>
            <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginBottom:14, alignItems:"center" }}>
              <span style={{ fontSize:10, color:C.muted, fontWeight:700, marginRight:2 }}>SEVERITY:</span>
              {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(f=>(
                <button key={f} style={fBtn(sevFilter===f,SEV[f]?.fg||C.navy)} onClick={()=>setSevFilter(f)}>{f}</button>
              ))}
              <span style={{ fontSize:10, color:C.muted, fontWeight:700, marginLeft:10, marginRight:2 }}>LAYER:</span>
              {["ALL","Signature","Statistical"].map(f=>(
                <button key={f} style={fBtn(layerFilter===f,f==="Signature"?C.blue:f==="Statistical"?C.purple:C.navy)}
                  onClick={()=>setLayerFilter(f)}>{f}</button>
              ))}
              <span style={{ marginLeft:"auto", fontSize:10, color:C.dim }}>{filtered.length} alerts</span>
            </div>

            <div style={{ display:"grid", gridTemplateColumns:selected?"1fr 400px":"1fr", gap:14 }}>
              <Panel style={{ maxHeight:"72vh", overflow:"hidden", display:"flex", flexDirection:"column" }}>
                <PanelHead icon="⚠" title="Alert Feed"/>
                <div style={{ flex:1, overflowY:"auto", padding:"8px 14px" }}>
                  {filtered.length===0&&<div style={{ color:C.dim, textAlign:"center", padding:32, fontSize:12 }}>No alerts match filters.</div>}
                  {filtered.map(a=>(
                    <div key={a.id} className="arow"
                      style={{ ...alertRow(a,selected?.id===a.id), animation:"fadeUp .25s ease" }}
                      onClick={()=>setSelected(a)}>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:4, flexWrap:"wrap" }}>
                          <SevChip sev={a.severity}/><LayerChip layer={a.layer}/>
                          <span style={{ fontSize:12, fontWeight:700, color:C.navy }}>{a.type}</span>
                          {a.real&&<Chip label="🔴 REAL" fg={C.crit} bg={C.critLt}/>}
                          <span style={{ fontSize:9, color:C.dim, marginLeft:"auto", fontFamily:"'JetBrains Mono',monospace" }}>{a.timestamp}</span>
                        </div>
                        <div style={{ fontSize:10, color:C.muted, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", marginBottom:2 }}>{a.log}</div>
                        <div style={{ display:"flex", gap:10, fontSize:9, color:C.dim, fontFamily:"'JetBrains Mono',monospace" }}>
                          <span>{a.ruleId}</span><span>{a.mitre}</span><span>{a.src} → {a.dst}</span><span>{a.confidence}%</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </Panel>

              {selected&&(
                <Panel style={{ animation:"fadeUp .25s ease", display:"flex", flexDirection:"column" }}>
                  <PanelHead icon="🔎" title="Alert Detail"
                    right={<button onClick={()=>setSelected(null)} style={{ background:"none",border:"none",color:C.dim,cursor:"pointer",fontSize:16 }}>✕</button>}/>
                  <div style={{ padding:"16px 18px", flex:1, overflowY:"auto" }}>
                    <div style={{ display:"flex", gap:6, marginBottom:10 }}>
                      <SevChip sev={selected.severity}/><LayerChip layer={selected.layer}/>
                    </div>
                    <div style={{ fontSize:16, fontWeight:800, color:C.navy, marginBottom:14 }}>{selected.type}</div>
                    {[
                      ["Timestamp",  selected.timestamp],
                      ["Source IP",  selected.src],
                      ["Destination",selected.dst],
                      ["Rule ID",    selected.ruleId],
                      ["MITRE",      selected.mitre],
                      ["Confidence", `${selected.confidence}%`],
                      ["Status",     selected.status],
                      ["Origin",     selected.real?"🔴 Real Traffic":"⚪ Simulation"],
                    ].map(([k,v])=>(
                      <div key={k} style={{ display:"flex", gap:8, marginBottom:7, alignItems:"flex-start" }}>
                        <span style={{ fontSize:10, color:C.muted, width:90, flexShrink:0, fontWeight:600 }}>{k}</span>
                        <span style={{ fontSize:10, color:C.text, fontFamily:"'JetBrains Mono',monospace", wordBreak:"break-all" }}>{v}</span>
                      </div>
                    ))}
                    <div style={{ background:C.bg, borderRadius:8, padding:"10px 12px", marginTop:8 }}>
                      <div style={{ fontSize:9, color:C.muted, fontWeight:700, letterSpacing:1.5, textTransform:"uppercase", marginBottom:5 }}>Raw Log</div>
                      <div style={{ fontSize:10, color:C.muted, lineHeight:1.7, wordBreak:"break-word", fontFamily:"'JetBrains Mono',monospace" }}>{selected.log}</div>
                    </div>
                    <button onClick={()=>analyzeAlert(selected)} style={{
                      marginTop:14, width:"100%",
                      background:`linear-gradient(135deg,${C.navy},${C.teal})`,
                      color:"#fff", border:"none", padding:"11px 16px",
                      borderRadius:10, cursor:"pointer", fontSize:12,
                      fontWeight:700, letterSpacing:.4,
                      boxShadow:`0 4px 14px ${C.navy}33`, fontFamily:"inherit",
                    }}>✦ Analyze with ARIA AI</button>
                  </div>
                </Panel>
              )}
            </div>
          </div>
        )}

        {/* ── RULES ──────────────────────────────────────────────── */}
        {tab==="rules" && (
          <div style={{ animation:"fadeUp .4s ease" }}>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
              {[
                {label:"Signature Layer",  cnt:8, color:C.blue,  fill:C.blueLt, rules:"RULE-003,004,005,006,009,013,014,015", desc:"Deterministic pattern matching"},
                {label:"Statistical Layer",cnt:7, color:C.purple,fill:C.purpLt, rules:"RULE-001,002,007,008,010,011,012",     desc:"Mathematical behavioral analysis"},
              ].map(l=>(
                <Panel key={l.label} style={{ borderTop:`3px solid ${l.color}` }}>
                  <div style={{ padding:"16px 20px" }}>
                    <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
                      <div style={{ fontSize:26, fontWeight:800, color:l.color, fontFamily:"'JetBrains Mono',monospace" }}>{l.cnt}</div>
                      <div>
                        <div style={{ fontSize:13, fontWeight:700, color:C.navy }}>{l.label}</div>
                        <div style={{ fontSize:10, color:C.muted }}>{l.desc}</div>
                      </div>
                    </div>
                    <div style={{ fontSize:9, color:C.dim, fontFamily:"'JetBrains Mono',monospace" }}>{l.rules}</div>
                  </div>
                </Panel>
              ))}
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10 }}>
              {Object.entries(RULES).map(([threat,rule])=>{
                const col = rule.layer==="Signature"?C.blue:C.purple;
                const sc  = SEV[rule.sev]||SEV.LOW;
                return (
                  <div key={rule.id} style={{
                    background:C.surface, borderRadius:10,
                    border:`1px solid ${C.border}`, borderLeft:`3px solid ${col}`,
                    padding:"12px 14px",
                    boxShadow:"0 1px 6px rgba(26,46,74,.06)",
                  }}>
                    <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:6 }}>
                      <span style={{ fontSize:10, fontWeight:700, color:col, fontFamily:"'JetBrains Mono',monospace" }}>{rule.id}</span>
                      <LayerChip layer={rule.layer}/>
                      <div style={{ marginLeft:"auto" }}><Chip label={rule.sev} fg={sc.fg} bg={sc.bg} size={9}/></div>
                    </div>
                    <div style={{ fontSize:12, fontWeight:700, color:C.navy, marginBottom:3 }}>{threat}</div>
                    <div style={{ fontSize:9, color:C.dim, fontFamily:"'JetBrains Mono',monospace" }}>{rule.mitre}</div>
                  </div>
                );
              })}
            </div>

            <Panel style={{ marginTop:14 }}>
              <div style={{ padding:"12px 18px", display:"flex", gap:24, flexWrap:"wrap" }}>
                {[
                  ["Rolling Window","All counters reset every 60 seconds"],
                  ["Detection","No ML training — purely rule-based and statistical"],
                  ["Performance","94.8% DR · 4.4% FPR · 142ms avg latency"],
                ].map(([k,v])=>(
                  <div key={k} style={{ fontSize:10, color:C.muted }}>
                    <span style={{ fontWeight:700, color:C.teal }}>{k}:</span> {v}
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        )}

        {/* ── LOGS ───────────────────────────────────────────────── */}
        {tab==="logs" && (
          <div style={{ display:"flex", flexDirection:"column", gap:14, animation:"fadeUp .4s ease" }}>
            <Panel style={{ border:`2px dashed ${C.border}`, display:"flex", flexDirection:"column", alignItems:"center", padding:"28px 20px", gap:10 }}>
              <div style={{ fontSize:38 }}>📁</div>
              <div style={{ fontSize:13, fontWeight:700, color:C.navy }}>Upload a real security log file</div>
              <div style={{ fontSize:10, color:C.dim }}>Supports .txt · .log · .csv · .json</div>
              <label style={{
                background:`linear-gradient(135deg,${C.navy},${C.teal})`,
                color:"#fff", padding:"9px 26px", borderRadius:10,
                cursor:"pointer", fontSize:11, fontWeight:700, letterSpacing:.4,
                boxShadow:`0 4px 12px ${C.navy}33`,
              }}>
                Choose File
                <input type="file" accept=".txt,.log,.csv,.json" style={{ display:"none" }} onChange={uploadLog}/>
              </label>
              {logFile&&(
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <span style={{ fontSize:11, color:C.teal, fontWeight:600 }}>✓ {logFile}</span>
                  <button onClick={analyzeLog} style={{
                    background:C.tealLt, color:C.teal, border:`1px solid ${C.teal}44`,
                    padding:"5px 14px", borderRadius:20, cursor:"pointer",
                    fontSize:10, fontWeight:700, fontFamily:"inherit",
                  }}>✦ Analyze with ARIA</button>
                </div>
              )}
            </Panel>

            <Panel style={{ maxHeight:"55vh", overflow:"hidden", display:"flex", flexDirection:"column" }}>
              <PanelHead icon="≡" title={logFile?`Real Log — ${logFile}`:"Simulated Log Stream"}
                right={logContent&&(
                  <button onClick={analyzeLog} style={{
                    background:C.navyLt, color:C.navy, border:`1px solid ${C.navy}33`,
                    padding:"3px 10px", borderRadius:20, cursor:"pointer",
                    fontSize:9, fontWeight:700, fontFamily:"inherit",
                  }}>✦ ARIA</button>
                )}/>
              <div style={{ flex:1, overflowY:"auto", padding:"6px 14px", fontFamily:"'JetBrains Mono',monospace" }}>
                {logContent
                  ? logContent.split("\n").map((line,i)=>(
                    <div key={i} style={{ padding:"3px 6px", borderBottom:`1px solid ${C.bg}`, fontSize:11, lineHeight:1.7,
                      color:/error|fail|attack|critical/i.test(line)?C.crit:/warn|suspect|alert/i.test(line)?C.high:/success|accept|allow/i.test(line)?C.teal:C.muted }}>
                      <span style={{ color:C.border, marginRight:10, userSelect:"none" }}>{i+1}</span>{line}
                    </div>
                  ))
                  : alerts.map((a,i)=>(
                    <div key={a.id} style={{ padding:"3px 6px", borderBottom:`1px solid ${C.bg}`, fontSize:11, lineHeight:1.7, animation:i<2?"fadeUp .3s ease":"none",
                      color:a.severity==="CRITICAL"?C.crit:a.severity==="HIGH"?C.high:a.severity==="MEDIUM"?C.med:C.teal }}>
                      <span style={{ color:C.dim, marginRight:10 }}>{a.timestamp}</span>
                      <span style={{ fontWeight:700, marginRight:8 }}>[{a.severity}]</span>
                      <span style={{ color:C.muted, marginRight:8 }}>[{a.ruleId}]</span>
                      {a.log}
                    </div>
                  ))
                }
              </div>
            </Panel>
          </div>
        )}

        {/* ── ARIA ───────────────────────────────────────────────── */}
        {tab==="aria" && (
          <div style={{ animation:"fadeUp .4s ease" }}>
            <Panel style={{ display:"flex", flexDirection:"column", height:"79vh" }}>
              <PanelHead icon="✦" title="ARIA — Automated Response Intelligence Analyst"
                right={
                  <div style={{ display:"flex", alignItems:"center", gap:6, fontSize:9, color:C.dim }}>
                    <div style={{ width:6,height:6,borderRadius:"50%",background:C.teal,animation:"pulse 2s ease-in-out infinite" }}/>
                    OpenRouter · Gemini 2.0 Flash
                  </div>
                }/>

              {/* Prompt chips */}
              <div style={{ padding:"10px 18px 8px", display:"flex", gap:6, flexWrap:"wrap", borderBottom:`1px solid ${C.border}` }}>
                {[
                  "What is hybrid intrusion detection?",
                  "How does C2 beaconing detection work?",
                  "Explain ARP spoofing",
                  "What is standard deviation analysis?",
                  "How do Sigma rules work?",
                  "How to reduce false positive rates?",
                  "Explain DNS tunneling detection",
                  "What is lateral movement?",
                ].map(p=>(
                  <button key={p} className="pchip"
                    onClick={()=>setChatInput(p)}
                    style={{ background:C.bg, border:`1px solid ${C.border}`, color:C.muted, padding:"4px 10px", borderRadius:20, cursor:"pointer", fontSize:9, fontWeight:500, transition:"all .15s", fontFamily:"inherit" }}>
                    {p}
                  </button>
                ))}
              </div>

              {/* Messages */}
              <div style={{ flex:1, overflowY:"auto", padding:"16px 18px", display:"flex", flexDirection:"column", gap:14 }}>
                {chat.map((m,i)=>(
                  <div key={i} style={{ display:"flex", justifyContent:m.role==="user"?"flex-end":"flex-start", animation:"fadeUp .3s ease" }}>
                    {m.role==="assistant"&&(
                      <div style={{ width:32, height:32, borderRadius:"50%", background:`linear-gradient(135deg,${C.navy},${C.teal})`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, marginRight:10, flexShrink:0, marginTop:2 }}>✦</div>
                    )}
                    <div style={{
                      maxWidth:"78%",
                      background:m.role==="user"?C.navy:C.surface,
                      color:m.role==="user"?"#fff":C.text,
                      border:m.role==="user"?"none":`1px solid ${C.border}`,
                      borderRadius:m.role==="user"?"14px 14px 4px 14px":"4px 14px 14px 14px",
                      padding:"11px 15px", fontSize:13, lineHeight:1.75,
                      whiteSpace:"pre-wrap", wordBreak:"break-word",
                      boxShadow:m.role==="user"?`0 3px 12px ${C.navy}33`:"0 2px 8px rgba(0,0,0,.05)",
                    }}>
                      {m.role==="assistant"&&<div style={{ fontSize:9, color:C.teal, fontWeight:700, letterSpacing:1.5, marginBottom:5 }}>ARIA</div>}
                      {m.content}
                    </div>
                  </div>
                ))}
                {chatLoading&&(
                  <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                    <div style={{ width:32,height:32,borderRadius:"50%",background:`linear-gradient(135deg,${C.navy},${C.teal})`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14 }}>✦</div>
                    <div style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:"4px 14px 14px 14px", padding:"11px 16px", fontSize:12, color:C.dim }}>
                      Analyzing<span style={{ animation:"pulse 1s ease-in-out infinite" }}>…</span>
                    </div>
                  </div>
                )}
                <div ref={chatEnd}/>
              </div>

              {/* Input */}
              <div style={{ padding:"12px 18px", borderTop:`1px solid ${C.border}`, display:"flex", gap:10 }}>
                <input
                  value={chatInput}
                  onChange={e=>setChatInput(e.target.value)}
                  onKeyDown={e=>e.key==="Enter"&&!e.shiftKey&&sendChat()}
                  placeholder="Ask ARIA about any alert, rule, threat, or incident response…"
                  style={{ flex:1, background:C.bg, border:`1px solid ${C.border}`, borderRadius:10, padding:"10px 14px", fontSize:13, color:C.text, outline:"none" }}
                />
                <button onClick={sendChat}
                  disabled={chatLoading||!chatInput.trim()}
                  style={{
                    background:chatInput.trim()&&!chatLoading?`linear-gradient(135deg,${C.navy},${C.teal})`:C.bg,
                    border:`1px solid ${chatInput.trim()&&!chatLoading?C.teal:C.border}`,
                    color:chatInput.trim()&&!chatLoading?"#fff":C.dim,
                    padding:"10px 22px", borderRadius:10,
                    cursor:chatInput.trim()&&!chatLoading?"pointer":"default",
                    fontSize:16, fontWeight:700, transition:"all .2s", fontFamily:"inherit",
                    boxShadow:chatInput.trim()&&!chatLoading?`0 3px 10px ${C.navy}33`:"none",
                  }}>➤</button>
              </div>
            </Panel>
          </div>
        )}
      </main>

      {/* ══ FOOTER ════════════════════════════════════════════════ */}
      <footer style={{
        borderTop:`1px solid ${C.border}`, padding:"8px 24px",
        display:"flex", justifyContent:"space-between",
        fontSize:9, color:C.dim, background:C.surface,
        fontFamily:"'JetBrains Mono',monospace",
      }}>
        <span>HYBRID NIDS SOC DASHBOARD · FINAL YEAR PROJECT · FATIMA SALISU U22CYS1117 · AFIT KADUNA</span>
        <span>SIG: 8 RULES · STAT: 7 RULES · DR: {dr.toFixed(1)}% · FPR: {fpr.toFixed(1)}% · LAT: {latency}ms</span>
        <span>ARIA v2.0 · OPENROUTER API</span>
      </footer>
    </div>
  );
}