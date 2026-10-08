"use strict";

async function checkHealth() {
  const status = document.getElementById("health");
  try {
    const response = await fetch("/health", { signal: AbortSignal.timeout(5000) });
    const result = await response.json();
    status.textContent = response.ok && result.status === "ok"
      ? "Local server is online."
      : "Local server health check failed.";
    if (window.consoleHealth) window.consoleHealth(response.ok && result.status === "ok");
  } catch {
    status.textContent = "Local server is unavailable.";
    if (window.consoleHealth) window.consoleHealth(false);
  }
}

checkHealth();

let user = null;
let selectedCase = null;
let offset = 0;
let caseRequest = 0;
const element = (id) => document.getElementById(id);

async function api(path, method = "GET", body) {
  const headers = { "Content-Type": "application/json" };
  if (user) headers["X-CSRF-Token"] = user.csrf_token;
  if (path === "/api/auth/login") headers["X-Spectre-Login"] = "1";
  const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(typeof error.detail === "string" ? error.detail : "Please check the entered values.");
  }
  return response.status === 204 ? null : response.json();
}

function showError(error) { element("message").textContent = error.message; }

async function refreshCases() {
  const cases = await api(`/api/cases?offset=${offset}`);
  element("cases").replaceChildren();
  if (!cases.length) element("cases").textContent = "No cases on this page.";
  for (const item of cases) {
    const button = document.createElement("button");
    button.textContent = `Case #${item.id} · ${item.title} · ${item.status}`;
    button.onclick = () => openCase(item.id).catch(showError);
    element("cases").append(button);
  }
  element("next-page").hidden = cases.length < 100;
}

async function openCase(id) {
  const request = ++caseRequest;
  const sameCase = selectedCase?.id === id;
  if (window.consoleCaseChanging) window.consoleCaseChanging(id);
  if (!sameCase && window.resetInvestigation) window.resetInvestigation();
  if (window.resetFindings) window.resetFindings();
  if (window.resetAI) window.resetAI();
  element("web-overview").hidden = true;
  webTargetId = null;
  element("domain-overview").hidden = true;
  domainTargetId = null;
  element("ip-overview").hidden = true;
  ipTargetId = null;
  resetTargetForm();
  targetOffset = 0;
  const result = await api(`/api/cases/${id}`);
  if (request !== caseRequest) return;
  selectedCase = result;
  if (window.configureFindings) window.configureFindings();
  element("case-detail").hidden = false;
  element("detail-title").textContent = `Case #${selectedCase.id} · ${selectedCase.title}`;
  element("detail-description").textContent = selectedCase.description;
  element("detail-status").textContent = `Status: ${selectedCase.status} · Owner ID: ${selectedCase.owner_id}`;
  element("edit-form").hidden = user.role === "viewer";
  element("member-form").hidden = !(user.role === "admin" || user.id === selectedCase.owner_id);
  element("edit-title").value = selectedCase.title;
  element("edit-description").value = selectedCase.description;
  element("edit-status").value = selectedCase.status;
  element("target-form").hidden = user.role === "viewer";
  await refreshTargets();
  if (request !== caseRequest) return;
  const auditRows = await api(`/api/cases/${id}/audit`);
  if (request !== caseRequest) return;
  element("audit").replaceChildren();
  for (const record of auditRows) {
    if (request !== caseRequest) return;
    const li = document.createElement("li");
    const detail=document.createElement("details"),summary=document.createElement("summary");
    summary.textContent=`${record.timestamp} · ${record.action.replaceAll("."," / ").replaceAll("_"," ")} · User #${record.actor_id}`;
    detail.append(summary);const metadata=document.createElement("pre");metadata.textContent=JSON.stringify(record.metadata||{},null,2);detail.append(metadata);li.append(detail);
    element("audit").append(li);
  }
  if (window.consoleCaseReady) await window.consoleCaseReady();
}

async function showWorkspace() {
  element("login-form").hidden = true;
  element("workspace").hidden = false;
  element("identity").textContent = `${user.username} · ${user.role} · User ID ${user.id}`;
  element("case-form").hidden = user.role === "viewer";
  if (window.consoleWorkspace) window.consoleWorkspace();
  await refreshCases();
}

element("login-form").onsubmit = async (event) => {
  event.preventDefault();
  element("message").textContent = "";
  try {
    user = await api("/api/auth/login", "POST", { username: element("username").value, password: element("password").value });
    offset = 0;
    await showWorkspace();
  } catch (error) { showError(error); }
  finally { element("password").value = ""; }
};
element("logout").onclick = async () => {
  try { await api("/api/auth/logout", "POST"); location.reload(); } catch (error) { showError(error); }
};
element("case-form").onsubmit = async (event) => {
  event.preventDefault();
  try {
    const created = await api("/api/cases", "POST", { title: element("case-title").value, description: element("case-description").value });
    event.target.reset(); offset = 0; await refreshCases(); await openCase(created.id);
  } catch (error) { showError(error); }
};
element("edit-form").onsubmit = async (event) => {
  event.preventDefault();
  try {
    await api(`/api/cases/${selectedCase.id}`, "PUT", { title: element("edit-title").value, description: element("edit-description").value, status: element("edit-status").value });
    await refreshCases(); await openCase(selectedCase.id);
  } catch (error) { showError(error); }
};
element("member-form").onsubmit = async (event) => {
  event.preventDefault();
  try {
    await api(`/api/cases/${selectedCase.id}/members/${element("member-id").value}`, event.submitter.value === "add" ? "PUT" : "DELETE");
    await openCase(selectedCase.id);
  } catch (error) { showError(error); }
};
element("next-page").onclick = async () => {
  offset += 100;
  try { await refreshCases(); } catch (error) { showError(error); }
};
api("/api/auth/me").then(async (identity) => { user = identity; await showWorkspace(); }).catch(() => {});

let editingTarget = null;
let targetOffset = 0;

function resetTargetForm() {
  editingTarget = null;
  element("target-form").reset();
  element("target-save").textContent = "Add target";
  element("target-cancel").hidden = true;
}

async function refreshTargets() {
  const id = selectedCase.id, request = caseRequest;
  const rows = await api(`/api/cases/${id}/targets?offset=${targetOffset}`);
  if (request !== caseRequest || selectedCase.id !== id) return;
  if (window.consoleTargets) window.consoleTargets(rows, targetOffset);
  element("targets").replaceChildren();
  if (!rows.length) element("targets").textContent = "No targets on this page.";
  for (const target of rows) {
    const row = document.createElement("section");
    const label = document.createElement("p");
    label.textContent = `Target #${target.id} · ${target.type}: ${target.value} · ${target.scope_status}${target.archived ? " · archived" : ""}`;
    const canonical = document.createElement("p");
    canonical.textContent = `Canonical value: ${target.normalized_value}`;
    row.append(label, canonical);
    const timestamps = document.createElement("p");
    timestamps.className = "target-meta";
    timestamps.textContent = `Created ${target.created_at} UTC · Updated ${target.updated_at} UTC`;
    row.append(timestamps);
    if (!target.archived) {
      const investigate=document.createElement("button");investigate.type="button";investigate.textContent="Investigate";
      investigate.onclick=()=>window.inspectStoredTarget(target).catch(showError);row.append(investigate);
    }
    if (target.type === "domain") {
      const overview = document.createElement("button");
      overview.type = "button";
      overview.textContent = "Domain overview";
      overview.onclick = () => openDomain(target).catch(showError);
      row.append(overview);
    }
    if (target.type === "url") {
      const overview = document.createElement("button");
      overview.type = "button";
      overview.textContent = "Web metadata";
      overview.onclick = () => openWeb(target).catch(showError);
      row.append(overview);
    }
    if (["ipv4", "ipv6"].includes(target.type)) {
      const overview = document.createElement("button");
      overview.type = "button";
      overview.textContent = "IP overview";
      overview.onclick = () => openIP(target).catch(showError);
      row.append(overview);
    }
    if (user.role !== "viewer") {
      const edit = document.createElement("button");
      edit.type = "button";
      edit.textContent = "Edit";
      edit.onclick = () => {
        editingTarget = target.id;
        element("target-type").value = target.type;
        element("target-value").value = target.value;
        element("target-scope").value = target.scope_status;
        element("target-save").textContent = "Save target";
        element("target-cancel").hidden = false;
        element("target-value").focus();
      };
      row.append(edit);
      if (!target.archived) {
        const archive = document.createElement("button");
        archive.type = "button";
        archive.textContent = "Archive";
        archive.onclick = async () => {
          try {
            await api(`/api/cases/${selectedCase.id}/targets/${target.id}`, "DELETE");
            await openCase(selectedCase.id);
          } catch (error) { showError(error); }
        };
        row.append(archive);
      }
    }
    element("targets").append(row);
  }
  element("targets-previous").hidden = targetOffset === 0;
  element("targets-next").hidden = rows.length < 100;
}

element("target-form").onsubmit = async (event) => {
  event.preventDefault();
  element("message").textContent = "";
  try {
    const path = `/api/cases/${selectedCase.id}/targets${editingTarget ? `/${editingTarget}` : ""}`;
    await api(path, editingTarget ? "PUT" : "POST", {
      type: element("target-type").value, value: element("target-value").value,
      scope_status: element("target-scope").value,
    });
    await openCase(selectedCase.id);
  } catch (error) { showError(error); }
};
element("target-cancel").onclick = resetTargetForm;
element("targets-previous").onclick = async () => {
  targetOffset = Math.max(0, targetOffset - 100);
  try { await refreshTargets(); } catch (error) { showError(error); }
};
element("targets-next").onclick = async () => {
  targetOffset += 100;
  try { await refreshTargets(); } catch (error) { showError(error); }
};

let domainTargetId = null;
let domainBusy = false;
let webTargetId = null;
let webBusy = false;

async function openWeb(target) {
  if (window.consoleNavigate) window.consoleNavigate("collectors");
  const caseId = selectedCase.id;
  if (webTargetId !== target.id) element("web-message").textContent = "";
  webTargetId = target.id;
  const data = await api(`/api/cases/${caseId}/targets/${target.id}/web`);
  const registry = await api(`/api/cases/${caseId}/collectors`);
  if (selectedCase.id !== caseId || webTargetId !== target.id) return;
  element("web-overview").hidden = false;
  element("web-heading").textContent = `Web metadata: ${data.url}`;
  element("web-scope").textContent = `Scope: ${data.scope_status}${target.archived ? " · archived" : ""}. ${data.limits}`;
  const provider = registry.find(item => item.name === "web_metadata");
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = `Collect web metadata${provider?.enabled ? "" : " (disabled)"}`;
  button.disabled = webBusy || !provider?.enabled || user.role === "viewer" || target.archived || target.scope_status === "excluded";
  button.onclick = async () => {
    webBusy = true; button.disabled = true;
    element("web-message").textContent = "Fetching one bounded public HTTPS page…";
    let message;
    try {
      const run = await api(`/api/cases/${caseId}/targets/${target.id}/collectors/web_metadata/runs`, "POST");
      message = `Run #${run.id}: ${run.status}${run.error_code ? ` (${run.error_code})` : ""}.`;
    } catch (error) { message = error.message; }
    finally {
      webBusy = false;
      if (selectedCase.id === caseId && webTargetId === target.id) {
        await openCase(caseId); await openWeb(target);
        element("web-message").textContent = message;
      }
    }
  };
  element("web-actions").replaceChildren(button);
  element("web-observations").replaceChildren(); element("web-runs").replaceChildren();
  for (const item of data.observations) {
    const group = document.createElement("section");
    const fact = text => citedFact(group, text, item.evidence_id);
    if (item.synthetic_fixture) fact("Synthetic fixture; not a live page observation");
    fact(`${item.parsed.provider} · captured ${item.captured_at} · run #${item.run_id} · SHA-256 ${item.sha256}`);
    for (const key of ["availability", "http_status", "requested_url", "final_url", "title", "title_state", "server_hint", "parse_note"]) if (item.parsed[key] !== undefined && item.parsed[key] !== null) fact(`${key}: ${item.parsed[key]}`);
    for (const [key, value] of Object.entries(item.parsed.headers || {})) fact(`${key}: ${value}`);
    for (const finding of item.parsed.findings || []) fact(`${finding.severity}: ${finding.header} — ${finding.observation}`);
    fact(item.parsed.caveat);
    element("web-observations").append(group);
  }
  if (!data.observations.length) element("web-observations").textContent = "No stored page evidence. Failed or blocked requests are not negative findings.";
  for (const run of data.runs) {
    const paragraph = document.createElement("p");
    paragraph.textContent = `Web metadata ${run.version} · run #${run.id} · ${run.status}${run.error_code ? ` (${run.error_code})` : ""} · ${run.started_at} · ${run.warnings_json.join("; ")}`;
    element("web-runs").append(paragraph);
  }
}
let ipTargetId = null;
let ipBusy = false;

async function openIP(target) {
  if (window.consoleNavigate) window.consoleNavigate("collectors");
  if (ipTargetId !== target.id) element("ip-message").textContent = "";
  ipTargetId = target.id;
  const caseId = selectedCase.id;
  const data = await api(`/api/cases/${caseId}/targets/${target.id}/ip`);
  const registry = await api(`/api/cases/${caseId}/collectors`);
  if (selectedCase.id !== caseId || ipTargetId !== target.id) return;
  element("ip-overview").hidden = false;
  element("ip-heading").textContent = `IP intelligence: ${data.ip}`;
  element("ip-scope").textContent = `Scope: ${data.scope_status}${target.archived ? " · archived" : ""}. ${data.limits}`;
  const names = {reverse_dns: "Reverse DNS", ip_rdap: "IP RDAP", ip_asn: "ASN / prefix"};
  element("ip-actions").replaceChildren();
  for (const provider of registry.filter(item => Object.hasOwn(names, item.name))) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `Collect ${names[provider.name]}${provider.enabled ? "" : " (disabled)"}`;
    button.disabled = ipBusy || !provider.enabled || user.role === "viewer" || target.archived || target.scope_status === "excluded";
    button.onclick = async () => {
      ipBusy = true;
      for (const control of element("ip-actions").querySelectorAll("button")) control.disabled = true;
      element("ip-message").textContent = `Collecting ${names[provider.name]} from its public provider…`;
      try {
        const run = await api(`/api/cases/${caseId}/targets/${target.id}/collectors/${provider.name}/runs`, "POST");
        if (selectedCase.id === caseId && ipTargetId === target.id) element("ip-message").textContent = `Run #${run.id}: ${run.status}${run.error_code ? ` (${run.error_code}); intelligence may be unavailable or partial` : ""}.`;
      } catch (error) { if (selectedCase.id === caseId && ipTargetId === target.id) element("ip-message").textContent = error.message; }
      finally {
        ipBusy = false;
        if (selectedCase.id === caseId && ipTargetId === target.id) {
          await openIP(target);
          element("audit").replaceChildren();
          for (const record of await api(`/api/cases/${caseId}/audit`)) {
            const li = document.createElement("li");
            const detail=document.createElement("details"),summary=document.createElement("summary");
    summary.textContent=`${record.timestamp} · ${record.action.replaceAll("."," / ").replaceAll("_"," ")} · User #${record.actor_id}`;
    detail.append(summary);const metadata=document.createElement("pre");metadata.textContent=JSON.stringify(record.metadata||{},null,2);detail.append(metadata);li.append(detail);
            element("audit").append(li);
          }
        }
      }
    };
    element("ip-actions").append(button);
  }
  for (const name of ["ptr", "rdap", "asn", "related", "runs"]) element(`ip-${name}`).replaceChildren();
  const sources = {reverse_dns: "ptr", ip_rdap_bootstrap: "rdap", ip_rdap: "rdap", ip_asn: "asn", ip_asn_holder: "asn"};
  for (const item of data.observations) {
    const group = document.createElement("section");
    if (item.synthetic_fixture) citedFact(group, "Synthetic test fixture — not a live provider observation", item.evidence_id);
    citedFact(group, `${item.parsed.provider} · captured ${item.captured_at} · run #${item.run_id}`, item.evidence_id);
    const hash = document.createElement("p");
    hash.className = "evidence-hash";
    hash.textContent = `SHA-256: ${item.sha256}`;
    group.append(hash);
    const parsed = item.parsed;
    const fact = text => citedFact(group, text, item.evidence_id);
    if (parsed.status === "error") {
      fact(`Provider unavailable: ${parsed.error_code}${parsed.http_status ? ` (HTTP ${parsed.http_status})` : ""}. This is not a negative finding.`);
    } else if (item.source_type === "reverse_dns") {
      fact(`Resolver response: ${parsed.rcode} · ${parsed.availability}`);
      for (const record of parsed.records) fact(`PTR: ${record.name} · TTL ${record.ttl}`);
    } else if (item.source_type === "ip_rdap_bootstrap") {
      fact(`Authoritative service: ${parsed.selected_base || "unavailable"} · bootstrap prefix: ${parsed.matched_prefix || "none observed"}`);
    } else if (item.source_type === "ip_rdap") {
      fact(`Allocation: ${parsed.start_address} – ${parsed.end_address} · ${parsed.name} · ${parsed.handle} · ${parsed.allocation_type}`);
      fact(`Registration statuses: ${parsed.statuses.join(", ") || "not supplied"}`);
      if (parsed.registration_country) fact(`Registration country: ${parsed.registration_country} (not physical geolocation)`);
      for (const organization of parsed.organizations) fact(`Organization: ${organization.name} · roles: ${organization.roles.join(", ")}`);
      for (const event of parsed.events) fact(`${event.action}: ${event.date}`);
    } else if (item.source_type === "ip_asn") {
      fact(`Prefix: ${parsed.prefix || "not observed"} · ${parsed.availability}`);
      fact(`Announcing ASNs: ${parsed.asns.map(value => `AS${value}`).join(", ") || "none observed by this provider"}`);
      if (parsed.provider_time) fact(`Provider response time: ${parsed.provider_time}`);
    } else if (item.source_type === "ip_asn_holder") {
      fact(`Holder metadata: ${parsed.availability || "not supplied in stored observation"}`);
      fact(`Prefix: ${parsed.prefix} · announced in this provider snapshot: ${parsed.announced_by_provider} · query time: ${parsed.query_time || "not supplied"}`);
      for (const holder of parsed.holders) fact(`AS${holder.asn} · holder: ${holder.holder || "not supplied"}`);
    }
    if (parsed.caveat) fact(parsed.caveat);
    element(`ip-${sources[item.source_type]}`).append(group);
  }
  for (const name of ["ptr", "rdap", "asn"]) if (!element(`ip-${name}`).childElementCount) element(`ip-${name}`).textContent = "No stored observations. Intelligence has not been established.";
  for (const relation of data.related_domains) citedFact(element("ip-related"), `${relation.domain} → resolves_to → ${data.ip} · confidence ${Math.round(relation.confidence * 100)}% (case DNS observation; not ownership)`, relation.evidence_id);
  if (!data.related_domains.length) element("ip-related").textContent = "No stored case DNS relationships in this view; not proof that no domains use this IP.";
  element("ip-reputation").textContent = data.reputation.message;
  for (const run of data.runs) {
    const paragraph = document.createElement("p");
    paragraph.textContent = `${names[run.collector]} ${run.version} · run #${run.id} · ${run.status}${run.error_code ? ` (${run.error_code})` : ""} · ${run.started_at} · ${run.warnings_json.join("; ")}`;
    element("ip-runs").append(paragraph);
  }
}

function domainEvidenceLink(evidenceId, caseId = selectedCase.id) {
  const link = document.createElement("a");
  link.href = `/api/cases/${caseId}/evidence/${evidenceId}`;
  link.target = "_blank";
  link.rel = "noopener";
  link.textContent = `Evidence #${evidenceId}`;
  return link;
}

function citedFact(parent, text, evidenceId) {
  const paragraph = document.createElement("p");
  paragraph.append(document.createTextNode(text + " · "), domainEvidenceLink(evidenceId));
  parent.append(paragraph);
}

async function openDomain(target) {
  if (window.consoleNavigate) window.consoleNavigate("collectors");
  if (domainTargetId !== target.id) element("domain-message").textContent = "";
  domainTargetId = target.id;
  const caseId = selectedCase.id;
  const data = await api(`/api/cases/${caseId}/targets/${target.id}/domain`);
  const registry = await api(`/api/cases/${caseId}/collectors`);
  if (selectedCase.id !== caseId || domainTargetId !== target.id) return;
  element("domain-overview").hidden = false;
  element("domain-heading").textContent = `Domain intelligence: ${data.domain}`;
  element("domain-scope").textContent = `Scope: ${data.scope_status}${target.archived ? " · archived" : ""}. ${data.limits}`;
  element("domain-actions").replaceChildren();
  for (const provider of registry.filter(item => ["dns", "rdap", "ct"].includes(item.name))) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `Collect ${provider.name.toUpperCase()}${provider.enabled ? "" : " (disabled)"}`;
    button.disabled = domainBusy || !provider.enabled || user.role === "viewer" || target.archived || target.scope_status === "excluded";
    button.onclick = async () => {
      domainBusy = true;
      for (const control of element("domain-actions").querySelectorAll("button")) control.disabled = true;
      element("domain-message").textContent = `Collecting ${provider.name.toUpperCase()} from its public source…`;
      try {
        const run = await api(`/api/cases/${caseId}/targets/${target.id}/collectors/${provider.name}/runs`, "POST");
        element("domain-message").textContent = `Run #${run.id}: ${run.status}${run.error_code ? ` (${run.error_code})` : ""}.`;
      } catch (error) { element("domain-message").textContent = error.message; }
      finally {
        domainBusy = false;
        if (selectedCase.id === caseId && domainTargetId === target.id) {
          await openDomain(target);
          element("audit").replaceChildren();
          for (const record of await api(`/api/cases/${caseId}/audit`)) {
            const li = document.createElement("li");
            const detail=document.createElement("details"),summary=document.createElement("summary");
    summary.textContent=`${record.timestamp} · ${record.action.replaceAll("."," / ").replaceAll("_"," ")} · User #${record.actor_id}`;
    detail.append(summary);const metadata=document.createElement("pre");metadata.textContent=JSON.stringify(record.metadata||{},null,2);detail.append(metadata);li.append(detail);
            element("audit").append(li);
          }
        }
      }
    };
    element("domain-actions").append(button);
  }
  for (const name of ["dns", "rdap", "ct", "infrastructure", "runs"]) element(`domain-${name}`).replaceChildren();
  for (const item of data.observations) {
    const source = item.source_type === "rdap_bootstrap" ? "rdap" : item.source_type;
    const parent = element(`domain-${source}`);
    if (!parent) continue;
    const group = document.createElement("section");
    if (item.synthetic_fixture) citedFact(group, "Synthetic test fixture — not a live provider observation", item.evidence_id);
    citedFact(group, `${item.parsed.provider} · captured ${item.captured_at} · run #${item.run_id}`, item.evidence_id);
    const hash = document.createElement("p");
    hash.className = "evidence-hash";
    hash.textContent = `SHA-256: ${item.sha256}`;
    group.append(hash);
    const parsed = item.parsed;
    if (parsed.status === "error") {
      citedFact(group, `Source unavailable: ${parsed.error_code}${parsed.http_status ? ` (HTTP ${parsed.http_status})` : ""}. Missing data is not a negative finding.`, item.evidence_id);
    } else if (source === "dns") {
      citedFact(group, `${parsed.query_type || "DNS"} query: ${parsed.rcode}`, item.evidence_id);
      for (const record of parsed.records || []) citedFact(group, `${record.owner} ${record.record_type} → ${record.value}${record.priority !== undefined ? ` (priority ${record.priority})` : ""} · TTL ${record.ttl}`, item.evidence_id);
    } else if (item.source_type === "rdap_bootstrap") {
      citedFact(group, `Authoritative service: ${parsed.selected_base || "unavailable"}`, item.evidence_id);
    } else if (source === "rdap") {
      citedFact(group, `Domain: ${parsed.domain} · registration handle: ${parsed.handle || "not supplied"}`, item.evidence_id);
      citedFact(group, `Registration statuses: ${parsed.statuses.join(", ") || "not supplied"}`, item.evidence_id);
      for (const event of parsed.events) citedFact(group, `${event.action}: ${event.date}`, item.evidence_id);
      for (const server of parsed.nameservers) citedFact(group, `Registered nameserver: ${server}`, item.evidence_id);
    } else if (source === "ct") {
      citedFact(group, parsed.coverage, item.evidence_id);
      for (const certificate of parsed.certificates) {
        citedFact(group, `Certificate ${certificate.sha256} · issuer: ${certificate.issuer || "not supplied"} · ${certificate.not_before} to ${certificate.not_after}`, item.evidence_id);
        for (const name of certificate.dns_names) citedFact(group, `Certificate names: ${name} (not proof of a live service)`, item.evidence_id);
        for (const base of certificate.wildcard_bases) citedFact(group, `Wildcard: *.${base} (no concrete subdomain inferred)`, item.evidence_id);
      }
    }
    parent.append(group);
  }
  for (const name of ["dns", "rdap", "ct"]) {
    if (!element(`domain-${name}`).childNodes.length) element(`domain-${name}`).textContent = "No stored observations yet.";
  }
  const nodes = new Map(data.entities.map(node => [node.id, node.value]));
  for (const relation of data.relationships) {
    citedFact(element("domain-infrastructure"), `${nodes.get(relation.from)} → ${relation.type} → ${nodes.get(relation.to)} · confidence ${Math.round(relation.confidence * 100)}%`, relation.evidence_id);
  }
  if (!data.relationships.length) element("domain-infrastructure").textContent = "No evidence-backed infrastructure relationships yet.";
  for (const run of data.runs) {
    const paragraph = document.createElement("p");
    paragraph.textContent = `${run.collector.toUpperCase()} ${run.version} · run #${run.id} · ${run.status}${run.error_code ? ` (${run.error_code})` : ""} · ${run.started_at} · ${run.warnings_json.join(" ")}`;
    element("domain-runs").append(paragraph);
  }
}
