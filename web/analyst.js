var alertsData = [];
var eventsData = [];
var selectedAlertId = null;

function byId(id){ return document.getElementById(id); }
function esc(value){
  return String(value == null ? "" : value).replace(/[&<>"']/g,function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];
  });
}
function niceTime(value){
  if(!value) return "—";
  var d = new Date(value);
  return isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}
function pillSeverity(value){
  var s = String(value || "low").toLowerCase();
  return '<span class="pill sev-' + esc(s) + '">' + esc(s) + '</span>';
}
function pillStatus(value){
  var s = String(value || "new").toLowerCase();
  return '<span class="pill status status-' + esc(s) + '">' + esc(s.replace("_"," ")) + '</span>';
}
async function request(url, options){
  var response = await fetch(url, Object.assign({cache:"no-store", credentials:"same-origin"}, options || {}));
  var data = {};
  try { data = await response.json(); } catch(e) {}
  if(!response.ok) throw new Error(data.error || ("HTTP " + response.status));
  return data;
}
async function post(action, payload){
  return request("/api/analyst?action=" + encodeURIComponent(action), {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(payload || {})
  });
}
function showConsole(){
  byId("login-view").hidden = true;
  byId("console-view").hidden = false;
  byId("logout").hidden = false;
}
function showLogin(){
  byId("login-view").hidden = false;
  byId("console-view").hidden = true;
  byId("logout").hidden = true;
}
async function checkSession(){
  try {
    var data = await request("/api/analyst?action=session");
    if(data.authenticated){ showConsole(); await loadDashboard(); }
    else showLogin();
  } catch(e) { showLogin(); byId("login-error").textContent = "Analyst API unavailable: " + e.message; }
}
byId("login-form").addEventListener("submit", async function(event){
  event.preventDefault();
  var button = event.currentTarget.querySelector("button");
  button.disabled = true;
  byId("login-error").textContent = "";
  try {
    await post("login", {password:byId("password").value});
    byId("password").value = "";
    showConsole();
    await loadDashboard();
  } catch(e) {
    byId("login-error").textContent = e.message;
  } finally { button.disabled = false; }
});
byId("logout").addEventListener("click", async function(){
  try { await post("logout", {}); } catch(e) {}
  showLogin();
  byId("password").value = "";
});
async function loadDashboard(){
  try {
    var results = await Promise.all([
      request("/api/analyst?action=overview"),
      request("/api/analyst?action=alerts&limit=150"),
      request("/api/analyst?action=events&limit=150")
    ]);
    var summary = results[0].summary || {};
    byId("event-total").textContent = Number(summary.events || 0).toLocaleString();
    byId("alert-total").textContent = Number(summary.alerts || 0).toLocaleString();
    byId("new-total").textContent = Number(summary.new_alerts || 0).toLocaleString();
    byId("critical-total").textContent = Number(summary.critical_open || 0).toLocaleString();
    byId("last-event").textContent = results[0].last_event ? niceTime(results[0].last_event.timestamp) : "No event timestamp available";
    alertsData = results[1] || [];
    eventsData = results[2] || [];
    renderAlerts();
    renderEvents();
  } catch(e) {
    if(e.message.indexOf("sign-in") >= 0){ showLogin(); return; }
    byId("alerts-list").innerHTML = '<tr><td colspan="4" class="empty">' + esc(e.message) + '</td></tr>';
    byId("events-list").innerHTML = '<tr><td colspan="6" class="empty">Unable to load endpoint events.</td></tr>';
  }
}
function filteredAlerts(){
  var q = byId("alert-search").value.trim().toLowerCase();
  var severity = byId("alert-severity").value;
  var status = byId("alert-status").value;
  return alertsData.filter(function(a){
    var text = [a.title,a.host,a.rule_id,a.entity,a.description].join(" ").toLowerCase();
    return (!q || text.indexOf(q)>=0) && (!severity || a.severity===severity) && (!status || a.status===status);
  });
}
function renderAlerts(){
  var rows = filteredAlerts();
  byId("alert-count").textContent = rows.length + " of " + alertsData.length + " alerts";
  if(!rows.length){
    byId("alerts-list").innerHTML = '<tr><td colspan="4" class="empty">No alerts match these filters.</td></tr>';
    return;
  }
  byId("alerts-list").innerHTML = rows.map(function(a){
    return '<tr data-alert-id="' + Number(a.id) + '" class="' + (Number(a.id)===Number(selectedAlertId)?"selected-row":"") + '">' +
      '<td><div class="event-title">' + esc(a.title) + '</div><div class="event-sub">' + esc(a.rule_id) + ' · ' + esc(a.host || "—") + '</div></td>' +
      '<td>' + pillSeverity(a.severity) + '</td><td>' + pillStatus(a.status) + '</td><td>' + esc(niceTime(a.timestamp)) + '</td></tr>';
  }).join("");
  Array.prototype.forEach.call(byId("alerts-list").querySelectorAll("tr[data-alert-id]"),function(row){
    row.addEventListener("click",function(){ selectAlert(Number(row.getAttribute("data-alert-id"))); });
  });
}
function selectAlert(id){
  selectedAlertId = id;
  var a = alertsData.find(function(item){ return Number(item.id)===Number(id); });
  if(!a) return;
  renderAlerts();
  var evidence = a.evidence || {};
  byId("alert-detail").classList.remove("empty-detail");
  byId("alert-detail").innerHTML =
    '<div class="eyebrow">' + esc(a.rule_id) + ' / ALERT #' + Number(a.id) + '</div>' +
    '<h3>' + esc(a.title) + '</h3>' +
    '<p>' + esc(a.description || "No additional description was supplied by the detection rule.") + '</p>' +
    '<div class="detail-meta"><div><small>Severity</small><b>' + esc(a.severity) + '</b></div><div><small>Timestamp</small><b>' + esc(niceTime(a.timestamp)) + '</b></div>' +
    '<div><small>Host</small><b>' + esc(a.host || "—") + '</b></div><div><small>Entity</small><b>' + esc(a.entity || "—") + '</b></div></div>' +
    '<label>Detection evidence</label><pre class="evidence">' + esc(JSON.stringify(evidence,null,2)) + '</pre>' +
    '<label for="triage-status">Investigation status</label><select id="triage-status">' +
    ['new','investigating','resolved','false_positive'].map(function(s){ return '<option value="' + s + '" ' + (a.status===s?'selected':'') + '>' + s.replace("_"," ") + '</option>'; }).join("") +
    '</select><label for="triage-notes">Analyst notes</label><textarea id="triage-notes" maxlength="4000" placeholder="Document what you checked, context and next steps…">' + esc(a.notes || "") + '</textarea>' +
    '<div class="detail-actions"><button id="save-triage" class="button primary">Save triage update</button></div>';
  byId("save-triage").addEventListener("click",saveTriage);
}
async function saveTriage(){
  var button = byId("save-triage");
  button.disabled = true;
  try {
    await post("triage", {
      id:selectedAlertId,
      status:byId("triage-status").value,
      notes:byId("triage-notes").value
    });
    await loadDashboard();
    selectAlert(selectedAlertId);
  } catch(e) { window.alert("Could not save triage: " + e.message); }
  finally { if(button) button.disabled = false; }
}
function filteredEvents(){
  var q = byId("event-search").value.trim().toLowerCase();
  var severity = byId("event-severity").value;
  return eventsData.filter(function(e){
    var text = [e.timestamp,e.host,e.source,e.product,e.category,e.action,e.outcome,e.message,e.source_ip,e.user,e.process,e.event_id].join(" ").toLowerCase();
    return (!q || text.indexOf(q)>=0) && (!severity || e.severity===severity);
  });
}
function renderEvents(){
  var rows = filteredEvents();
  byId("event-count").textContent = rows.length + " of " + eventsData.length + " events";
  if(!rows.length){
    byId("events-list").innerHTML = '<tr><td colspan="6" class="empty">No events match these filters.</td></tr>';
    return;
  }
  byId("events-list").innerHTML = rows.map(function(e){
    return '<tr data-event-id="' + Number(e.id) + '">' +
      '<td><div class="event-title">' + esc(e.action || e.category || "Event") + '</div><div class="event-sub">' + esc(e.category || "—") + ' · ID ' + esc(e.event_id || "—") + '</div></td>' +
      '<td>' + esc(e.host || "—") + '</td><td>' + esc(e.source || "—") + '</td>' +
      '<td class="event-user">' + esc(e.user || "—") + '<div class="event-sub">' + esc(e.process || "—") + '</div></td>' +
      '<td>' + pillSeverity(e.severity) + '<div class="event-sub">' + esc(e.outcome || "—") + '</div></td><td>' + esc(niceTime(e.timestamp)) + '</td></tr>';
  }).join("");
  Array.prototype.forEach.call(byId("events-list").querySelectorAll("tr[data-event-id]"),function(row){
    row.addEventListener("click",function(){
      var item = eventsData.find(function(e){ return Number(e.id)===Number(row.getAttribute("data-event-id")); });
      if(!item) return;
      byId("event-detail").hidden = false;
      byId("event-detail").innerHTML = '<h3>Event record #' + Number(item.id) + ' · ' + esc(item.action || item.category || "Event") + '</h3><pre>' + esc(JSON.stringify(item,null,2)) + '</pre>';
      Array.prototype.forEach.call(byId("events-list").querySelectorAll("tr"),function(r){r.classList.remove("selected-row");});
      row.classList.add("selected-row");
    });
  });
}
['alert-search','alert-severity','alert-status'].forEach(function(id){ byId(id).addEventListener("input",renderAlerts); });
['event-search','event-severity'].forEach(function(id){ byId(id).addEventListener("input",renderEvents); });
byId("refresh").addEventListener("click",loadDashboard);
checkSession();
