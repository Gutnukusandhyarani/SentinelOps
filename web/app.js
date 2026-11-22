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
loadAll(); setInterval(loadAll,15000);
