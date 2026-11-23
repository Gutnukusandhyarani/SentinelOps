const $ = id => document.getElementById(id);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const niceTime = value => { try { return new Date(value).toLocaleString(); } catch { return value || "—"; } };
async function get(path){const response=await fetch(path,{cache:"no-store"});if(!response.ok)throw new Error(`HTTP ${response.status}`);return response.json();}
function severity(value){const s=String(value||"low").toLowerCase();return `<span class="pill sev-${esc(s)}">${esc(s)}</span>`;}
function status(value){const s=String(value||"new");return `<span class="pill status status-${esc(s)}">${esc(s.replace("_"," "))}</span>`;}
async function triage(id){
  const alerts=await get("/api/alerts?limit=500");
  const current=alerts.find(item=>Number(item.id)===Number(id));
  if(!current){alert("Alert no longer exists.");return;}
  const next=prompt("Set status: new, investigating, resolved, false_positive",current.status||"investigating");
  if(next===null)return;
  const clean=next.trim().toLowerCase();
  if(!["new","investigating","resolved","false_positive"].includes(clean)){alert("Invalid status.");return;}
  const analystNotes=prompt("Analyst notes (optional):",current.notes||"");
  if(analystNotes===null)return;
  const result=await fetch(`/api/alerts/${id}/triage`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({status:clean,notes:analystNotes})});
  if(!result.ok){alert("Unable to update alert.");return;} await loadAll();
}
async function loadAll(){
  try{
    const [summary,alerts,events]=await Promise.all([get("/api/summary"),get("/api/alerts?limit=50"),get("/api/events?limit=50")]);
    $("m-events").textContent=summary.events.toLocaleString();
    $("m-alerts").textContent=summary.alerts.toLocaleString();
    $("m-new").textContent=summary.new_alerts.toLocaleString();
    $("m-critical").textContent=summary.critical_open.toLocaleString();
    $("nav-alerts").textContent=summary.new_alerts;
    $("alert-count").textContent=`${alerts.length} records`;
    $("event-count").textContent=`${events.length} records`;
    $("alerts-body").innerHTML=alerts.length?alerts.map(a=>`<tr>
      <td><div class="event-title">${esc(a.title)}</div><div class="event-sub">${esc(a.rule_id)} · ${esc(a.host)}</div></td>
      <td>${severity(a.severity)}</td><td>${esc(a.entity||"—")}</td><td>${esc(niceTime(a.timestamp))}</td>
      <td>${status(a.status)}</td><td><button class="triage" onclick='triage(${Number(a.id)})'>Review</button></td></tr>`).join(""):`<tr><td colspan="6" class="empty">No alerts yet. Ingest endpoint logs to begin.</td></tr>`;
    $("events-body").innerHTML=events.length?events.map(e=>`<tr>
      <td><div class="event-title">${esc(e.action)}</div><div class="event-sub">${esc(e.category)} · ID ${esc(e.event_id||"—")}</div></td>
      <td>${esc(e.host)}</td><td>${esc(e.source)}${e.source_ip?`<div class="event-sub">${esc(e.source_ip)}</div>`:""}</td>
      <td>${esc(e.user||"—")}</td><td>${esc(e.outcome)}</td><td>${esc(niceTime(e.timestamp))}</td></tr>`).join(""):`<tr><td colspan="6" class="empty">No events ingested yet.</td></tr>`;
  }catch(e){console.error(e);$("alerts-body").innerHTML=`<tr><td colspan="6" class="empty">Dashboard API unavailable: ${esc(e.message)}</td></tr>`;}
}
/* dashboard startup is selected by /api/config below */

async function loadPublicDashboard(){
  try{
    const [summary,activity]=await Promise.all([get("/api/public_summary"),get("/api/public_activity")]);
    $("pub-events").textContent=Number(summary.events||0).toLocaleString();
    $("pub-alerts").textContent=Number(summary.alerts||0).toLocaleString();
    $("pub-new").textContent=Number(summary.new_alerts||0).toLocaleString();
    $("pub-critical").textContent=Number(summary.critical_open||0).toLocaleString();
    const last=summary.last_event_at?new Date(summary.last_event_at):null;
    $("public-status").textContent=Number(summary.events||0)>0?"Event records available":"Waiting for endpoint data";
    $("public-last-event").textContent=last && !Number.isNaN(last.getTime())?`Most recent event timestamp: ${last.toLocaleString()} (no identifying fields are displayed).`:"No endpoint event has been received yet. Connect an authorized collector to begin.";
    const max=Math.max(1,...activity.map(d=>Number(d.events||0)));
    $("public-activity").innerHTML=activity.map(d=>{const count=Number(d.events||0),alerts=Number(d.alerts||0),height=Math.max(3,Math.round(count/max*100));return `<div class="activity-day" title="${esc(d.day)}: ${count} events, ${alerts} alerts"><div class="activity-bar-wrap"><div class="activity-bar" style="height:${height}%"></div></div><b>${count}</b><small>${esc(String(d.day).slice(5))}</small></div>`;}).join("") || `<p class="empty">No activity to display.</p>`;
    const sev=summary.alerts_by_severity||{};
    const order=["critical","high","medium","low","info"];
    const total=order.reduce((n,k)=>n+Number(sev[k]||0),0);
    $("public-severity").innerHTML=order.map(k=>`<div class="severity-row"><span class="severity-dot sev-${k}"></span><span>${k}</span><b>${Number(sev[k]||0).toLocaleString()}</b><span class="severity-track"><i style="width:${total?Math.round(Number(sev[k]||0)/total*100):0}%"></i></span></div>`).join("");
  }catch(e){console.error(e);$("public-status").textContent=`Dashboard unavailable: ${esc(e.message)}`;}
}

async function startDashboard(){
  try{
    const config=await get("/api/config");
    if(config.public_mode){
      document.body.classList.add("public-mode");
      $("public-dashboard").hidden=false;
      await loadPublicDashboard();
      setInterval(loadPublicDashboard,15000);
      return;
    }
  }catch(e){console.error("Dashboard configuration unavailable",e);}
  loadAll(); setInterval(loadAll,15000);
}
startDashboard();
