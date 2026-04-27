import { useState, useEffect, useRef, useCallback } from "react";
import { io } from "socket.io-client";

// Hybrid Network-Based IDS SOC Dashboard
// Detection: Signature-Based Rules + Statistical Anomaly Analysis
// Analyst Support: ARIA (LLM via OpenRouter API)
// Author: Fatima Salisu — U22CYS1117 — AFIT Kaduna

const THREAT_TYPES = [
  "Port Scan","SYN Flood / DDoS","SSH Brute Force","RDP Brute Force",
  "FTP Brute Force","C2 Beaconing","DNS Tunneling","ARP Spoofing / MITM",
  "Lateral Movement","Data Exfiltration","SQL Injection","Directory Traversal",
  "ICMP Flood","Suspicious Port Connection","Telnet Brute Force",
];

const MITRE_MAP = {
  "Port Scan":"T1046","SYN Flood / DDoS":"T1498","SSH Brute Force":"T1110",
  "RDP Brute Force":"T1110.001","FTP Brute Force":"T1110","C2 Beaconing":"T1071",
  "DNS Tunneling":"T1071.004","ARP Spoofing / MITM":"T1557.002","Lateral Movement":"T1021",
  "Data Exfiltration":"T1041","SQL Injection":"T1190","Directory Traversal":"T1083",
  "ICMP Flood":"T1498.001","Suspicious Port Connection":"T1571","Telnet Brute Force":"T1110",
};

const RULE_MAP = {
  "Port Scan":"RULE-001","SYN Flood / DDoS":"RULE-002","SSH Brute Force":"RULE-003",
  "RDP Brute Force":"RULE-004","FTP Brute Force":"RULE-005","Telnet Brute Force":"RULE-006",
  "C2 Beaconing":"RULE-007","DNS Tunneling":"RULE-008","ARP Spoofing / MITM":"RULE-009",
  "Lateral Movement":"RULE-010","Data Exfiltration":"RULE-011","ICMP Flood":"RULE-012",
  "Suspicious Port Connection":"RULE-013","SQL Injection":"RULE-014","Directory Traversal":"RULE-015",
};

const DETECTION_LAYER = {
  "Port Scan":"Statistical","SYN Flood / DDoS":"Statistical","SSH Brute Force":"Statistical",
  "RDP Brute Force":"Statistical","FTP Brute Force":"Statistical","Telnet Brute Force":"Statistical",
  "C2 Beaconing":"Statistical","DNS Tunneling":"Statistical","ARP Spoofing / MITM":"Signature",
  "Lateral Movement":"Statistical","Data Exfiltration":"Statistical","ICMP Flood":"Statistical",
  "Suspicious Port Connection":"Signature","SQL Injection":"Signature","Directory Traversal":"Signature",
};

const SOURCES = ["192.168.1.45","10.0.0.23","172.16.5.89","203.0.113.12","198.51.100.7","192.0.2.55","10.10.5.200","172.31.0.44"];

const LOG_TEMPLATES = [
  (src,type) => `[NET] ${type} detected from ${src} — rule: ${RULE_MAP[type]||"RULE-000"}`,
  (src,type) => `[IDS] Threshold exceeded for ${type} — src: ${src} | layer: ${DETECTION_LAYER[type]||"Hybrid"}`,
  (src,type) => `[NIDS] Anomalous traffic from ${src} — alert: ${type} | MITRE: ${MITRE_MAP[type]||"T0000"}`,
  (src,type) => `[AGENT] Detection engine flagged ${src} for ${type} — hybrid analysis triggered`,
  (src,type) => `[STAT] Statistical baseline violation from ${src} — category: ${type}`,
  (src,type) => `[SIG] Signature rule matched on traffic from ${src} — threat: ${type}`,
];

const rand = (arr) => arr[Math.floor(Math.random()*arr.length)];
const randFloat = (min,max) => (Math.random()*(max-min)+min).toFixed(1);
const randInt = (min,max) => Math.floor(Math.random()*(max-min+1))+min;

function generateAlert() {
  const severity = Math.random();
  const type = rand(THREAT_TYPES);
  const src = rand(SOURCES);
  const layer = DETECTION_LAYER[type];
  const confMin = layer==="Signature"?88:78;
  const confMax = layer==="Signature"?99:97;
  return {
    id: Date.now()+Math.random(),
    timestamp: new Date().toISOString().replace("T"," ").slice(0,19),
    type, source: src, destination: rand(SOURCES),
    severity: severity>0.75?"CRITICAL":severity>0.45?"HIGH":severity>0.2?"MEDIUM":"LOW",
    confidence: parseFloat(randFloat(confMin,confMax)),
    detectionLayer: layer||"Hybrid",
    ruleId: RULE_MAP[type]||"RULE-000",
    mitre: MITRE_MAP[type]||"T0000",
    log: rand(LOG_TEMPLATES)(src,type),
    status:"NEW", real:false,
    falsePositive: Math.random()<0.044,
  };
}

function SeverityBadge({sev}) {
  const colors={CRITICAL:"#ff3b3b",HIGH:"#ff8c00",MEDIUM:"#ffd600",LOW:"#00e5a0"};
  return <span style={{background:colors[sev]+"22",color:colors[sev],border:`1px solid ${colors[sev]}55`,padding:"2px 8px",borderRadius:3,fontSize:11,fontWeight:700,letterSpacing:1,fontFamily:"monospace"}}>{sev}</span>;
}

function LayerBadge({layer}) {
  const colors={"Signature":{bg:"#00b4ff22",color:"#00b4ff",border:"#00b4ff55"},"Statistical":{bg:"#c060ff22",color:"#c060ff",border:"#c060ff55"},"Hybrid":{bg:"#00e5a022",color:"#00e5a0",border:"#00e5a055"}};
  const c=colors[layer]||colors["Hybrid"];
  return <span style={{background:c.bg,color:c.color,border:`1px solid ${c.border}`,padding:"2px 7px",borderRadius:3,fontSize:10,fontWeight:600,letterSpacing:0.5,fontFamily:"monospace"}}>{layer}</span>;
}

function MetricCard({label,value,sub,accent,pulse}) {
  return (
    <div style={{background:"linear-gradient(135deg,#0d1520 0%,#0a1219 100%)",border:`1px solid ${accent}33`,borderRadius:8,padding:"18px 22px",minWidth:120,flex:1,position:"relative",overflow:"hidden"}}>
      <div style={{position:"absolute",top:0,left:0,right:0,height:2,background:`linear-gradient(90deg,transparent,${accent},transparent)`,animation:pulse?"scanline 2s ease-in-out infinite":"none"}} />
      <div style={{color:"#4a6380",fontSize:11,letterSpacing:1.5,fontFamily:"monospace",marginBottom:6}}>{label}</div>
      <div style={{color:accent,fontSize:26,fontWeight:800,fontFamily:"'Courier New',monospace",lineHeight:1}}>{value}</div>
      {sub&&<div style={{color:"#3a5068",fontSize:10,marginTop:4,fontFamily:"monospace"}}>{sub}</div>}
    </div>
  );
}

function ThreatBarChart({data}) {
  const max=Math.max(...Object.values(data),1);
  return (
    <div style={{display:"flex",flexDirection:"column",gap:6}}>
      {Object.entries(data).slice(0,8).map(([k,v])=>(
        <div key={k} style={{display:"flex",alignItems:"center",gap:8}}>
          <div style={{width:130,fontSize:10,color:"#4a7090",fontFamily:"monospace",textAlign:"right",flexShrink:0}}>{k.length>18?k.slice(0,16)+"..":k}</div>
          <div style={{flex:1,height:12,background:"#0a1219",borderRadius:2,overflow:"hidden"}}>
            <div style={{width:`${(v/max)*100}%`,height:"100%",background:DETECTION_LAYER[k]==="Signature"?"linear-gradient(90deg,#00b4ff,#0080ff)":"linear-gradient(90deg,#c060ff,#8040ff)",borderRadius:2,transition:"width 0.6s ease",minWidth:v>0?4:0}} />
          </div>
          <div style={{width:28,fontSize:10,color:"#00e5a0",fontFamily:"monospace",textAlign:"right"}}>{v}</div>
        </div>
      ))}
      <div style={{display:"flex",gap:16,marginTop:6}}>
        <div style={{display:"flex",alignItems:"center",gap:5,fontSize:9,color:"#00b4ff"}}><div style={{width:8,height:8,borderRadius:1,background:"#00b4ff"}} /> Signature Layer</div>
        <div style={{display:"flex",alignItems:"center",gap:5,fontSize:9,color:"#c060ff"}}><div style={{width:8,height:8,borderRadius:1,background:"#c060ff"}} /> Statistical Layer</div>
      </div>
    </div>
  );
}

function DetectionGauge({label,value,color}) {
  const pct=Math.min(Math.max(value,0),100);
  const r=32,cx=40,cy=40,circ=2*Math.PI*r,dash=(pct/100)*circ;
  return (
    <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4}}>
      <svg width={80} height={80}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#0d1f2e" strokeWidth={8}/>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={8} strokeDasharray={`${dash} ${circ-dash}`} strokeLinecap="round" transform={`rotate(-90 ${cx} ${cy})`} style={{transition:"stroke-dasharray 0.8s ease"}}/>
        <text x={cx} y={cy+5} textAnchor="middle" fill={color} fontSize={13} fontWeight="bold" fontFamily="monospace">{Math.round(pct)}%</text>
      </svg>
      <span style={{fontSize:10,color:"#3a6080",fontFamily:"monospace",letterSpacing:1,textAlign:"center"}}>{label}</span>
    </div>
  );
}

async function askARIA(messages) {
  const systemPrompt = `You are ARIA (Automated Response Intelligence Analyst), an expert AI analyst embedded in a hybrid network-based SOC dashboard — final year cybersecurity project at AFIT Kaduna by Fatima Salisu (U22CYS1117).

HYBRID DETECTION ENGINE — two layers:
1. SIGNATURE LAYER: ARP spoofing MAC comparison (RULE-009), suspicious port lookup (RULE-013), SQL injection pattern (RULE-014), directory traversal (RULE-015)
2. STATISTICAL LAYER: port scan counting (RULE-001), SYN flood rate (RULE-002), brute force tracking (RULE-003 to 006), C2 beacon std deviation (RULE-007), DNS payload averaging (RULE-008), lateral movement tracking (RULE-010), exfiltration byte counting (RULE-011), ICMP rate (RULE-012)

Detection Rules (Table 3.1):
RULE-001: Port Scan (>15 unique ports/min) T1046 | RULE-002: SYN Flood (>100 SYN/s) T1498
RULE-003: SSH BruteForce (>10/min port22) T1110 | RULE-004: RDP BruteForce (>10/min port3389) T1110.001
RULE-005: FTP BruteForce (>10/min port21) T1110 | RULE-006: Telnet BruteForce (>10/min port23) T1110
RULE-007: C2 Beacon (std_dev<5s intervals) T1071 | RULE-008: DNS Tunnel (avg query>100B) T1071.004
RULE-009: ARP Spoof (MAC change for known IP) T1557.002 | RULE-010: Lateral Movement (>10 hosts/min) T1021
RULE-011: Data Exfil (>50MB/min outbound) T1041 | RULE-012: ICMP Flood (>50/s) T1498.001
RULE-013: Suspicious Port (4444,1337,31337) T1571 | RULE-014: SQL Inject (HTTP path) T1190 | RULE-015: Dir Traversal T1083

Performance (Table 4.2): DR=94.8%, FPR=4.4%, Avg Latency=142ms.
Be concise and technical. Reference rule IDs and MITRE techniques. Frame outputs as analyst decision support.`;

  const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method:"POST",
    headers:{"Content-Type":"application/json","Authorization":`Bearer ${import.meta.env.VITE_OPENROUTER_API_KEY}`,"HTTP-Referer":"https://soc-dashboard.vercel.app","X-Title":"SOC Nexus AFIT"},
    body:JSON.stringify({model:"google/gemini-2.0-flash:free",messages:[{role:"system",content:systemPrompt},...messages.map(m=>({role:m.role,content:m.content}))]})
  });
  const data = await response.json();
  return data.choices?.[0]?.message?.content || "⚠ No response. Check VITE_OPENROUTER_API_KEY in .env";
}

export default function SOCDashboard() {
  const [alerts,setAlerts] = useState(()=>Array.from({length:12},generateAlert));
  const [selected,setSelected] = useState(null);
  const [tab,setTab] = useState("dashboard");
  const [chat,setChat] = useState([{role:"assistant",content:"ARIA online. I am your hybrid IDS analyst assistant.\n\nThis SOC uses a two-layer detection engine:\n• Signature Layer — deterministic rule matching (RULE-009,013,014,015)\n• Statistical Layer — behavioral threshold analysis (RULE-001 to 008, 010-012)\n\nAsk me about any alert, detection rule, MITRE technique, or incident response."}]);
  const [chatInput,setChatInput] = useState("");
  const [chatLoading,setChatLoading] = useState(false);
  const [threatCounts,setThreatCounts] = useState({});
  const [layerCounts,setLayerCounts] = useState({Signature:0,Statistical:0});
  const [metrics,setMetrics] = useState({total:0,critical:0,fp:0});
  const [paused,setPaused] = useState(false);
  const [filter,setFilter] = useState("ALL");
  const [layerFilter,setLayerFilter] = useState("ALL");
  const [detectionRate,setDetectionRate] = useState(94.8);
  const [fpRate,setFpRate] = useState(4.4);
  const [latency,setLatency] = useState(142);
  const [agentConnected,setAgentConnected] = useState(false);
  const [uploadedLogContent,setUploadedLogContent] = useState(null);
  const [uploadedFileName,setUploadedFileName] = useState(null);
  const chatEndRef = useRef(null);
  const socket = useRef(null);

  // Ref for mutable alert generation interval
  const alertIntervalRef = useRef(null);

  // Alert history limits
  const ALERT_HISTORY_LIMIT = 50;

  useEffect(() => {
    // Initialize WebSocket connection
    socket.current = io("http://localhost:5000");

    socket.current.on("connect", () => {
      console.log("WebSocket connected");
      setAgentConnected(true);
      socket.current.emit("request_history", { limit: ALERT_HISTORY_LIMIT });
    });

    socket.current.on("disconnect", () => {
      console.log("WebSocket disconnected");
      setAgentConnected(false);
    });

    socket.current.on("alert_history", (data) => {
      console.log("Alert history received", data);
      setAlerts(data.alerts.reverse()); // Reverse to show latest first
    });

    socket.current.on("real_alert", (alert) => {
      console.log("Real alert received", alert);
      setAlerts((prev) => [alert, ...prev.slice(0, ALERT_HISTORY_LIMIT - 1)]);

      // Update counts for real alerts
      setThreatCounts((prev) => ({ ...prev, [alert.type]: (prev[alert.type] || 0) + 1 }));
      setLayerCounts((prev) => ({ ...prev, [alert.detectionLayer]: (prev[alert.detectionLayer] || 0) + 1 }));
      setMetrics((prev) => ({
        total: prev.total + 1,
        critical: prev.critical + (alert.severity === "CRITICAL" ? 1 : 0),
        fp: prev.fp + (alert.falsePositive ? 1 : 0),
      }));
    });

    // Cleanup on component unmount
    return () => {
      socket.current.disconnect();
    };
  }, []); // Run only once on mount

  // Simulate alerts when not connected to agent or paused
  useEffect(() => {
    if (agentConnected || paused) {
      clearInterval(alertIntervalRef.current);
      return;
    }

    alertIntervalRef.current = setInterval(() => {
      const a = generateAlert();
      setAlerts((prev) => [a, ...prev.slice(0, ALERT_HISTORY_LIMIT - 1)]);
      setThreatCounts((prev) => ({ ...prev, [a.type]: (prev[a.type] || 0) + 1 }));
      setLayerCounts((prev) => ({ ...prev, [a.detectionLayer]: (prev[a.detectionLayer] || 0) + 1 }));
      setMetrics((prev) => ({
        total: prev.total + 1,
        critical: prev.critical + (a.severity === "CRITICAL" ? 1 : 0),
        fp: prev.fp + (a.falsePositive ? 1 : 0),
      }));
      setDetectionRate((d) => Math.min(99.0, Math.max(90.0, d + (Math.random() - 0.5) * 0.3)));
      setFpRate((f) => Math.min(10.0, Math.max(2.0, f + (Math.random() - 0.5) * 0.2)));
      setLatency((l) => Math.min(380, Math.max(48, l + randInt(-15, 15))));
    }, 2800);

    return () => clearInterval(alertIntervalRef.current);
  }, [paused, agentConnected]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chat]);

  useEffect(() => {
    // Fetch initial stats from REST API
    fetch("http://localhost:5000/api/stats")
      .then((res) => res.json())
      .then((data) => {
        setMetrics({ total: data.total_alerts, critical: data.critical_alerts, fp: data.false_positives });
        setThreatCounts(data.threat_type_counts);
        setLayerCounts(data.detection_layer_counts);
      })
      .catch((error) => console.error("Failed to fetch stats:", error));
  }, [agentConnected]); // Refetch when agent connects/disconnects

  const sendChat=useCallback(async()=>{
    if(!chatInput.trim()||chatLoading)return;
    const userMsg={role:"user",content:chatInput};
    const newChat=[...chat,userMsg];
    setChat(newChat);setChatInput("");setChatLoading(true);
    try{const reply=await askARIA(newChat);setChat(prev=>[...prev,{role:"assistant",content:reply}]);}
    catch{setChat(prev=>[...prev,{role:"assistant",content:"⚠ Connection interrupted. Check VITE_OPENROUTER_API_KEY in .env"}]);}
    setChatLoading(false);
  },[chat,chatInput,chatLoading]);

  const analyzeAlert=useCallback(async(alert)=>{
    setTab("chat");
    const msg=`Analyze this SOC alert:\n\n- Threat: ${alert.type}\n- Severity: ${alert.severity}\n- Source: ${alert.source}\n- Destination: ${alert.destination}\n- Detection Layer: ${alert.detectionLayer}\n- Rule ID: ${alert.ruleId}\n- MITRE: ${alert.mitre}\n- Confidence: ${alert.confidence}%\n- FP Flag: ${alert.falsePositive?"Possible FP (4.4% base rate)":"Unlikely FP"}\n- Log: ${alert.log}\n\nProvide: (1) threat assessment, (2) attack stage, (3) response actions, (4) FP likelihood.`;
    const userMsg={role:"user",content:msg};
    const newChat=[...chat,userMsg];
    setChat(newChat);setChatLoading(true);
    try{const reply=await askARIA(newChat);setChat(prev=>[...prev,{role:"assistant",content:reply}]);}
    catch{setChat(prev=>[...prev,{role:"assistant",content:"⚠ ARIA analysis failed."}]);}
    setChatLoading(false);
  },[chat]);

  const handleFileUpload=useCallback((e)=>{
    const file=e.target.files[0];if(!file)return;
    setUploadedFileName(file.name);
    const reader=new FileReader();
    reader.onload=(ev)=>setUploadedLogContent(ev.target.result);
    reader.readAsText(file);
  },[]);

  const analyzeUploadedLog = useCallback(async () => {
    if (!uploadedLogContent) return;
    setTab("chat");

    setChat((prev) => [
      ...prev,
      { role: "user", content: `Analyzing uploaded log file: ${uploadedFileName}` },
      { role: "assistant", content: "Initiating log analysis..." },
    ]);
    setChatLoading(true);

    try {
      const response = await fetch("http://localhost:5000/api/logs/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: uploadedLogContent, filename: uploadedFileName }),
      });
      const data = await response.json();

      if (data.status === "ok" && data.flagged_entries) {
        let analysisOutput = `Log file analysis complete for **${uploadedFileName}**\n\n`;
        if (data.flagged_entries.length > 0) {
          analysisOutput += `**${data.flagged_entries.length} potential threats identified:**\n`;
          data.flagged_entries.forEach((entry) => {
            analysisOutput += `• 
Timestamp: ${entry.timestamp}, 
Line: ${entry.line_number}, 
Threat: ${entry.threat_type || "N/A"}, 
Rule: ${entry.rule_id || "N/A"}, 
MITRE: ${entry.mitre_id || "N/A"}\n`;
          });
          analysisOutput += `\nSeverity: ${data.overall_severity || "MEDIUM"}, 
Summary: ${data.summary || "Review flagged entries for further investigation."}`;
        } else {
          analysisOutput += "No specific threats identified based on current rules. Further manual review recommended if anomalies are suspected.";
        }

        setChat((prev) => [...prev, { role: "assistant", content: analysisOutput }]);
        // Optionally, fetch updated logs to show new parsed entries
        // fetchLogs();
      } else {
        setChat((prev) => [...prev, { role: "assistant", content: `⚠ Log analysis failed: ${data.message || "Unknown error."}` }]);
      }
    } catch (error) {
      console.error("Error analyzing uploaded log:", error);
      setChat((prev) => [
        ...prev,
        { role: "assistant", content: "⚠ Failed to connect to log analysis service." },
      ]);
    }
    setChatLoading(false);
  }, [uploadedLogContent, uploadedFileName, chat]);

  const filteredAlerts=alerts.filter(a=>{
    return(filter==="ALL"||a.severity===filter)&&(layerFilter==="ALL"||a.detectionLayer===layerFilter);
  });

  const S={
    root:{minHeight:"100vh",background:"#060d14",color:"#c8e0f0",fontFamily:"'Courier New','Consolas',monospace",display:"flex",flexDirection:"column"},
    header:{background:"linear-gradient(180deg,#0a1520 0%,#060d14 100%)",borderBottom:"1px solid #0f2035",padding:"12px 28px",display:"flex",alignItems:"center",justifyContent:"space-between",gap:16,position:"sticky",top:0,zIndex:100},
    navBtn:(a)=>({padding:"7px 18px",background:a?"#00e5a011":"transparent",color:a?"#00e5a0":"#3a6080",border:a?"1px solid #00e5a033":"1px solid transparent",borderRadius:6,cursor:"pointer",fontSize:12,letterSpacing:1,transition:"all 0.2s"}),
    main:{flex:1,padding:"20px 28px",display:"flex",flexDirection:"column",gap:20},
    panel:{background:"linear-gradient(145deg,#0b1825 0%,#080f18 100%)",border:"1px solid #0f2035",borderRadius:10,padding:"18px 20px",overflow:"hidden"},
    panelTitle:{fontSize:11,letterSpacing:2,color:"#2a5070",marginBottom:14,display:"flex",alignItems:"center",gap:8,textTransform:"uppercase"},
    alertRow:(sev,sel)=>({display:"flex",alignItems:"flex-start",gap:10,padding:"9px 10px",borderRadius:6,cursor:"pointer",background:sel?"#00e5a008":"transparent",borderLeft:`3px solid ${sev==="CRITICAL"?"#ff3b3b":sev==="HIGH"?"#ff8c00":sev==="MEDIUM"?"#ffd600":"#00e5a0"}`,marginBottom:4,transition:"background 0.15s"}),
    chatBubble:(role)=>({maxWidth:"82%",alignSelf:role==="user"?"flex-end":"flex-start",background:role==="user"?"#00e5a018":"#0d1e2e",border:`1px solid ${role==="user"?"#00e5a033":"#0f2035"}`,borderRadius:10,padding:"10px 14px",fontSize:13,lineHeight:1.6,color:role==="user"?"#a0f0d0":"#b0cce0",whiteSpace:"pre-wrap",wordBreak:"break-word"}),
  };

  return (
    <div style={S.root}>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}@keyframes scanline{0%{opacity:0;transform:translateX(-100%)}50%{opacity:1}100%{opacity:0;transform:translateX(100%)}}@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:#060d14}::-webkit-scrollbar-thumb{background:#0f2035;border-radius:3px}*{box-sizing:border-box}`}</style>

      <header style={S.header}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:36,height:36,background:"linear-gradient(135deg,#00e5a0,#00b4ff)",borderRadius:8,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,boxShadow:"0 0 16px #00e5a040"}}>🛡</div>
          <div>
            <div style={{fontSize:18,fontWeight:800,color:"#e8f4ff",letterSpacing:2}}>SOC · NEXUS</div>
            <div style={{fontSize:10,color:"#2a5070",letterSpacing:3,marginTop:-2}}>HYBRID NIDS — SIGNATURE + STATISTICAL DETECTION</div>
          </div>
        </div>
        <nav style={{display:"flex",gap:4}}>
          {["dashboard","alerts","logs","chat"].map(t=>(
            <button key={t} style={S.navBtn(tab===t)} onClick={()=>setTab(t)}>
              {t==="dashboard"?"⬡ DASHBOARD":t==="alerts"?"⚠ ALERTS":t==="logs"?"≡ LOGS":"✦ ARIA"}
            </button>
          ))}
        </nav>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{display:"flex",alignItems:"center",gap:6,fontSize:10,color:agentConnected?"#00e5a0":"#ff8c00"}}>
            <div style={{width:7,height:7,borderRadius:"50%",background:agentConnected?"#00e5a0":"#ff8c00",boxShadow:`0 0 6px ${agentConnected?"#00e5a0":"#ff8c00"}`,animation:"pulse 2s ease-in-out infinite"}} />
            {agentConnected?"AGENT LIVE":"SIM MODE"}
          </div>
          <div style={{display:"flex",alignItems:"center",gap:6,fontSize:11,color:"#2a5070"}}>
            <div style={{width:8,height:8,borderRadius:"50%",background:paused?"#ff8c00":"#00e5a0",boxShadow:`0 0 8px ${paused?"#ff8c00":"#00e5a0"}`,animation:"pulse 2s ease-in-out infinite"}} />
            {paused?"PAUSED":"LIVE"}
          </div>
          <button onClick={()=>setPaused(p=>!p)} style={{background:paused?"#ff8c0015":"#00e5a015",border:`1px solid ${paused?"#ff8c0040":"#00e5a040"}`,color:paused?"#ff8c00":"#00e5a0",padding:"5px 12px",borderRadius:5,cursor:"pointer",fontSize:11,letterSpacing:1}}>
            {paused?"▶ RESUME":"⏸ PAUSE"}
          </button>
          <div style={{fontSize:11,color:"#1a3050",letterSpacing:1}}>{new Date().toLocaleTimeString()}</div>
        </div>
      </header>

      <main style={S.main}>

        {tab==="dashboard"&&<>
          <div style={{display:"flex",gap:12}}>
            <MetricCard label="TOTAL EVENTS" value={metrics.total} sub="session total" accent="#00b4ff" pulse />
            <MetricCard label="CRITICAL" value={metrics.critical} sub="active threats" accent="#ff3b3b" pulse />
            <MetricCard label="SIG DETECTIONS" value={layerCounts.Signature||0} sub="signature layer" accent="#00b4ff" />
            <MetricCard label="STAT DETECTIONS" value={layerCounts.Statistical||0} sub="statistical layer" accent="#c060ff" />
            <MetricCard label="FALSE POS." value={metrics.fp} sub={`${metrics.total>0?((metrics.fp/metrics.total)*100).toFixed(1):4.4}% rate`} accent="#ffd600" />
            <MetricCard label="LATENCY MS" value={latency} sub="avg detection" accent="#00e5a0" />
          </div>

          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
            <div style={S.panel}>
              <div style={S.panelTitle}>⬡ Threat Distribution by Detection Layer</div>
              <ThreatBarChart data={threatCounts} />
              {Object.keys(threatCounts).length===0&&<div style={{color:"#1a3050",fontSize:12,textAlign:"center",padding:20}}>Awaiting detection events…</div>}
            </div>
            <div style={S.panel}>
              <div style={S.panelTitle}>◈ Hybrid Engine Performance — Table 4.2</div>
              <div style={{display:"flex",justifyContent:"space-around",marginBottom:16}}>
                <DetectionGauge label="DETECTION RATE" value={detectionRate} color="#00e5a0" />
                <DetectionGauge label="PRECISION" value={100-fpRate*4} color="#00b4ff" />
                <DetectionGauge label="F1 SCORE" value={(detectionRate+(100-fpRate*4))/2} color="#c060ff" />
                <DetectionGauge label="FP RATE INV." value={100-fpRate*10} color="#ffd600" />
              </div>
              <div style={{borderTop:"1px solid #0f2035",paddingTop:12}}>
                <div style={S.panelTitle}>Detection Engine Layers</div>
                {[{name:"Signature Layer",rules:"RULE-009,013,014,015",load:72,color:"#00b4ff"},{name:"Statistical Layer",rules:"RULE-001–008,010–012",load:88,color:"#c060ff"},{name:"ARIA Analyst",rules:"OpenRouter API",load:45,color:"#00e5a0"}].map(({name,rules,load,color})=>(
                  <div key={name} style={{marginBottom:8}}>
                    <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}>
                      <span style={{fontSize:11,color:"#3a6080"}}>{name}</span>
                      <span style={{fontSize:9,color:"#1a3050"}}>{rules}</span>
                      <span style={{fontSize:10,color,fontWeight:700}}>{load}%</span>
                    </div>
                    <div style={{height:6,background:"#080f18",borderRadius:2,overflow:"hidden"}}>
                      <div style={{width:`${load}%`,height:"100%",borderRadius:2,background:color,transition:"width 0.6s ease"}} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div style={S.panel}>
            <div style={S.panelTitle}>⚡ Live Alert Stream <span style={{marginLeft:"auto",fontSize:10,color:"#00e5a050"}}>{alerts.length} events buffered</span></div>
            <div style={{maxHeight:260,overflowY:"auto"}}>
              {alerts.slice(0,8).map(a=>(
                <div key={a.id} style={S.alertRow(a.severity,selected?.id===a.id)} onClick={()=>{setSelected(a);setTab("alerts")}}>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                      <SeverityBadge sev={a.severity}/><LayerBadge layer={a.detectionLayer}/>
                      <span style={{fontSize:12,color:"#90c0e0",fontWeight:600}}>{a.type}</span>
                      <span style={{fontSize:10,color:"#1a3050",marginLeft:"auto"}}>{a.ruleId} · {a.mitre}</span>
                      <span style={{fontSize:11,color:"#2a5070"}}>{a.timestamp}</span>
                    </div>
                    <div style={{fontSize:10,color:"#2a5070",marginTop:3,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>src: {a.source} → dst: {a.destination} · conf: {a.confidence}%</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>}

        {tab==="alerts"&&<>
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(f=>(
              <button key={f} onClick={()=>setFilter(f)} style={{padding:"5px 14px",background:filter===f?"#00e5a018":"transparent",border:`1px solid ${filter===f?"#00e5a055":"#0f2035"}`,color:filter===f?"#00e5a0":"#2a5070",borderRadius:5,cursor:"pointer",fontSize:11,letterSpacing:1}}>{f}</button>
            ))}
            <div style={{width:1,background:"#0f2035",margin:"0 4px"}} />
            {["ALL","Signature","Statistical"].map(f=>(
              <button key={f} onClick={()=>setLayerFilter(f)} style={{padding:"5px 14px",background:layerFilter===f?(f==="Signature"?"#00b4ff18":f==="Statistical"?"#c060ff18":"#ffffff08"):"transparent",border:`1px solid ${layerFilter===f?(f==="Signature"?"#00b4ff55":f==="Statistical"?"#c060ff55":"#ffffff22"):"#0f2035"}`,color:layerFilter===f?(f==="Signature"?"#00b4ff":f==="Statistical"?"#c060ff":"#c8e0f0"):"#2a5070",borderRadius:5,cursor:"pointer",fontSize:11,letterSpacing:1}}>
                {f==="ALL"?"ALL LAYERS":f}
              </button>
            ))}
            <span style={{marginLeft:"auto",fontSize:11,color:"#2a5070",alignSelf:"center"}}>{filteredAlerts.length} alerts</span>
          </div>

          <div style={{display:"grid",gridTemplateColumns:selected?"1fr 400px":"1fr",gap:16}}>
            <div style={{...S.panel,maxHeight:"70vh",overflowY:"auto"}}>
              {filteredAlerts.map(a=>(
                <div key={a.id} style={{...S.alertRow(a.severity,selected?.id===a.id),animation:"fadeIn 0.3s ease"}} onClick={()=>setSelected(a)}>
                  <div style={{flex:1}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                      <SeverityBadge sev={a.severity}/><LayerBadge layer={a.detectionLayer}/>
                      <span style={{fontSize:13,color:"#a0c8e8",fontWeight:700}}>{a.type}</span>
                      {a.falsePositive&&<span style={{fontSize:10,background:"#ffd60015",color:"#ffd600",border:"1px solid #ffd60033",padding:"1px 6px",borderRadius:3}}>POSSIBLE FP</span>}
                      {a.real&&<span style={{fontSize:10,background:"#ff3b3b15",color:"#ff3b3b",border:"1px solid #ff3b3b33",padding:"1px 6px",borderRadius:3}}>🔴 REAL</span>}
                      <span style={{fontSize:11,color:"#1a3050",marginLeft:"auto"}}>{a.timestamp}</span>
                    </div>
                    <div style={{fontSize:11,color:"#2a5070",lineHeight:1.6,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{a.log}</div>
                    <div style={{display:"flex",gap:12,marginTop:4,fontSize:10,color:"#1a3050"}}>
                      <span>src: {a.source}</span><span>{a.ruleId}</span><span>{a.mitre}</span><span>conf: {a.confidence}%</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {selected&&(
              <div style={{...S.panel,animation:"fadeIn 0.25s ease"}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:14}}>
                  <div style={S.panelTitle}>Alert Detail</div>
                  <button onClick={()=>setSelected(null)} style={{background:"none",border:"none",color:"#2a5070",cursor:"pointer",fontSize:16}}>✕</button>
                </div>
                <div style={{display:"flex",flexDirection:"column",gap:10}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                    <SeverityBadge sev={selected.severity}/><LayerBadge layer={selected.detectionLayer}/>
                    <span style={{fontSize:13,fontWeight:700,color:"#c8e0f0"}}>{selected.type}</span>
                  </div>
                  {[["Timestamp",selected.timestamp],["Source IP",selected.source],["Destination",selected.destination],["Rule ID",selected.ruleId],["MITRE",selected.mitre],["Detection Layer",selected.detectionLayer],["Confidence",`${selected.confidence}%`],["Status",selected.status],["False Positive",selected.falsePositive?"Possible (4.4% base rate)":"Unlikely"],["Origin",selected.real?"🔴 Real Network Event":"Simulation"]].map(([k,v])=>(
                    <div key={k} style={{display:"flex",gap:8}}>
                      <span style={{fontSize:11,color:"#2a5070",width:110,flexShrink:0}}>{k}</span>
                      <span style={{fontSize:11,color:"#7ab0d0"}}>{v}</span>
                    </div>
                  ))}
                  <div style={{borderTop:"1px solid #0f2035",paddingTop:10,marginTop:4}}>
                    <div style={{fontSize:10,color:"#2a5070",marginBottom:6}}>RAW LOG</div>
                    <div style={{fontSize:11,color:"#507090",lineHeight:1.6,background:"#050b12",padding:"8px 10px",borderRadius:5,wordBreak:"break-all"}}>{selected.log}</div>
                  </div>
                  <button onClick={()=>analyzeAlert(selected)} style={{marginTop:6,background:"linear-gradient(90deg,#00e5a020,#00b4ff20)",border:"1px solid #00e5a040",color:"#00e5a0",padding:"9px 16px",borderRadius:6,cursor:"pointer",fontSize:12,letterSpacing:1,fontFamily:"monospace"}}>
                    ✦ ANALYZE WITH ARIA
                  </button>
                </div>
              </div>
            )}
          </div>
        </>}

        {tab==="logs"&&(
          <div style={{display:"flex",flexDirection:"column",gap:16}}>
            <div style={{...S.panel,border:"1px dashed #0f3050",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",padding:30,gap:12}}>
              <div style={{fontSize:28}}>📁</div>
              <div style={{fontSize:13,color:"#4a7090",fontFamily:"monospace"}}>Upload a real log file for hybrid IDS analysis</div>
              <div style={{fontSize:11,color:"#1a3050",fontFamily:"monospace"}}>Supports: .txt · .log · .csv · .json — analyzed against RULE-001 to RULE-015</div>
              <label style={{background:"linear-gradient(90deg,#00e5a020,#00b4ff20)",border:"1px solid #00e5a040",color:"#00e5a0",padding:"9px 24px",borderRadius:6,cursor:"pointer",fontSize:12,letterSpacing:1,fontFamily:"monospace"}}>
                CHOOSE FILE<input type="file" accept=".txt,.log,.csv,.json" style={{display:"none"}} onChange={handleFileUpload}/>
              </label>
              {uploadedFileName&&<div style={{fontSize:11,color:"#00e5a0",fontFamily:"monospace"}}>✓ Loaded: {uploadedFileName}</div>}
            </div>
            <div style={{...S.panel,maxHeight:"50vh",overflow:"hidden",display:"flex",flexDirection:"column"}}>
              <div style={{...S.panelTitle,justifyContent:"space-between"}}>
                <span>≡ {uploadedFileName?`Real Log — ${uploadedFileName}`:"Simulated Detection Log Stream"}</span>
                {uploadedLogContent&&<button onClick={analyzeUploadedLog} style={{background:"linear-gradient(90deg,#00e5a020,#00b4ff20)",border:"1px solid #00e5a040",color:"#00e5a0",padding:"4px 12px",borderRadius:5,cursor:"pointer",fontSize:11,fontFamily:"monospace",letterSpacing:1}}>✦ ANALYZE WITH ARIA</button>}
              </div>
              <div style={{flex:1,overflowY:"auto",fontFamily:"monospace"}}>
                {uploadedLogContent?(
                  uploadedLogContent.split("\n").map((line,i)=>(
                    <div key={i} style={{padding:"4px 8px",borderBottom:"1px solid #080f18",fontSize:11,lineHeight:1.6,color:/error|fail|attack|brute|flood|scan|inject|spoof|exfil/i.test(line)?"#ff6060":/warn|suspicious|anomal/i.test(line)?"#ffa040":/success|accept|allow/i.test(line)?"#50a880":"#4a7090"}}>
                      <span style={{color:"#1a3050",marginRight:10,userSelect:"none"}}>{i+1}</span>{line}
                    </div>
                  ))
                ):(
                  alerts.map((a,i)=>(
                    <div key={a.id} style={{padding:"5px 8px",borderBottom:"1px solid #080f18",fontSize:11,lineHeight:1.6,color:a.severity==="CRITICAL"?"#ff6060":a.severity==="HIGH"?"#ffa040":a.severity==="MEDIUM"?"#ffe060":"#50a880",animation:i<2?"fadeIn 0.3s ease":"none"}}>
                      <span style={{color:"#1a3050",marginRight:10}}>{a.timestamp}</span>
                      <span style={{color:"#2a5070",marginRight:8}}>[{a.severity}]</span>
                      <span style={{color:"#1a3050",marginRight:8}}>[{a.ruleId}]</span>
                      {a.log}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {tab==="chat"&&(
          <div style={{...S.panel,flex:1,display:"flex",flexDirection:"column",maxHeight:"75vh"}}>
            <div style={S.panelTitle}>
              ✦ ARIA — Automated Response Intelligence Analyst
              <span style={{marginLeft:"auto",fontSize:10,color:"#00e5a050"}}>OpenRouter API · LLM Decision Support</span>
            </div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:12}}>
              {["How is C2 beaconing detected using standard deviation?","Explain ARP spoofing signature detection","Signature vs statistical layer — what is the difference?","How to reduce false positives in threshold detection?","Explain MITRE T1110 brute force technique","What does RULE-007 detect and how?"].map(p=>(
                <button key={p} onClick={()=>setChatInput(p)} style={{background:"#0a1520",border:"1px solid #0f2035",color:"#2a5070",padding:"4px 10px",borderRadius:4,cursor:"pointer",fontSize:10,letterSpacing:0.5,transition:"all 0.2s"}}
                  onMouseEnter={e=>{e.target.style.color="#00b4ff";e.target.style.borderColor="#00b4ff33"}}
                  onMouseLeave={e=>{e.target.style.color="#2a5070";e.target.style.borderColor="#0f2035"}}>{p}</button>
              ))}
            </div>
            <div style={{flex:1,overflowY:"auto",display:"flex",flexDirection:"column",gap:10,paddingRight:4}}>
              {chat.map((m,i)=>(
                <div key={i} style={{display:"flex",justifyContent:m.role==="user"?"flex-end":"flex-start",animation:"fadeIn 0.3s ease"}}>
                  <div style={S.chatBubble(m.role)}>
                    {m.role==="assistant"&&<div style={{fontSize:10,color:"#00e5a060",marginBottom:4,letterSpacing:1}}>ARIA</div>}
                    {m.content}
                  </div>
                </div>
              ))}
              {chatLoading&&(
                <div style={{display:"flex",justifyContent:"flex-start"}}>
                  <div style={{...S.chatBubble("assistant"),color:"#00e5a050"}}>
                    <div style={{fontSize:10,color:"#00e5a060",marginBottom:4,letterSpacing:1}}>ARIA</div>Analyzing… ▋
                  </div>
                </div>
              )}
              <div ref={chatEndRef}/>
            </div>
            <div style={{display:"flex",gap:8,marginTop:12,borderTop:"1px solid #0f2035",paddingTop:12}}>
              <input value={chatInput} onChange={e=>setChatInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&!e.shiftKey&&sendChat()}
                placeholder="Ask ARIA about any alert, detection rule, or incident…"
                style={{flex:1,background:"#050b12",border:"1px solid #0f2035",borderRadius:6,padding:"10px 14px",color:"#90c0e0",fontSize:12,fontFamily:"monospace",outline:"none"}}/>
              <button onClick={sendChat} disabled={chatLoading||!chatInput.trim()} style={{background:chatInput.trim()&&!chatLoading?"linear-gradient(135deg,#00e5a0,#00b4ff)":"#0a1520",border:"none",color:chatInput.trim()&&!chatLoading?"#060d14":"#1a3050",padding:"10px 20px",borderRadius:6,cursor:chatInput.trim()&&!chatLoading?"pointer":"default",fontSize:13,fontWeight:700,transition:"all 0.2s"}}>➤</button>
            </div>
          </div>
        )}

      </main>

      <div style={{borderTop:"1px solid #0a1825",padding:"8px 28px",display:"flex",justifyContent:"space-between",fontSize:10,color:"#1a3050",letterSpacing:1}}>
        <span>HYBRID NIDS SOC · FINAL YEAR PROJECT · AFIT KADUNA · FATIMA SALISU U22CYS1117</span>
        <span>SIGNATURE LAYER · STATISTICAL LAYER · ARIA v1.0</span>
        <span>DR: 94.8% · FPR: 4.4% · AVG LATENCY: 142ms</span>
      </div>
    </div>
  );
}
