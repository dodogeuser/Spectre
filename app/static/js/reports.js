"use strict";
(() => {
  const el=id=>document.getElementById(id);
  let generation=0,busy=false,canExport=false;
  const valid=(id,token)=>selectedCase?.id===id&&generation===token;
  const controls=()=>{for(const format of ["html","pdf"])el(`reports-${format}`).disabled=busy||!canExport;el("reports-refresh").disabled=busy;el("reports-redact").disabled=busy;};
  const append=(parent,tag,value)=>{const node=document.createElement(tag);node.textContent=value;parent.append(node);return node;};
  window.resetReports=()=>{++generation;busy=false;canExport=false;el("reports-preview").replaceChildren();el("reports-status").textContent="Open Reports to preview the authorized case.";controls();};
  async function preview(){
    if(!selectedCase||busy)return;
    const id=selectedCase.id,token=++generation;busy=true;canExport=false;controls();el("reports-status").textContent="Verifying stored evidence and preparing report preview…";
    el("reports-preview").replaceChildren();
    try{
      const data=await api(`/api/cases/${id}/reports/preview?redact_notes=${el("reports-redact").checked}`);
      if(!valid(id,token))return;
      const panel=el("reports-preview");append(panel,"h3",`Case #${data.case.id}: ${data.case.title}`);
      append(panel,"p",`Status: ${data.case.status} · Owner: ${data.case.owner} · Created: ${data.case.created_at}`);
      append(panel,"p",data.case.description||"No case description stored.");
      const list=document.createElement("dl");for(const [name,count]of Object.entries(data.counts)){append(list,"dt",name.replaceAll("_"," "));append(list,"dd",count);}panel.append(list);
      append(panel,"p",`Report v${data.report_version} · Snapshot SHA-256: ${data.snapshot_sha256}`);
      append(panel,"p",data.limitations);
      canExport=data.can_export;el("reports-status").textContent=canExport?"Preview ready. Downloads include a stored graph schematic, full indexes and evidence provenance. Export success is audited.":"Preview ready. Viewer access is read-only; exporting requires investigator or administrator access.";
    }catch(error){if(valid(id,token))el("reports-status").textContent=error.message;}
    finally{if(valid(id,token)){busy=false;controls();}}
  }
  async function download(format){
    if(!selectedCase||busy||!canExport)return;
    const id=selectedCase.id,token=++generation;busy=true;controls();el("reports-status").textContent=`Generating ${format.toUpperCase()} from stored case data…`;
    try{
      const response=await fetch(`/api/cases/${id}/reports/export`,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":user.csrf_token},body:JSON.stringify({format,redact_notes:el("reports-redact").checked})});
      if(!response.ok){const error=await response.json();throw Error(typeof error.detail==="string"?error.detail:"Report export rejected.");}
      const blob=await response.blob();if(!valid(id,token))return;
      const url=URL.createObjectURL(blob),link=document.createElement("a");link.href=url;link.download=`spectre-case-${id}.${format}`;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);
      el("reports-status").textContent=`${format.toUpperCase()} download prepared for Case #${id}. Review the report before sharing.`;
    }catch(error){if(valid(id,token))el("reports-status").textContent=error.message;}
    finally{if(valid(id,token)){busy=false;controls();}}
  }
  window.openReports=preview;
  el("reports-refresh").onclick=preview;el("reports-redact").onchange=preview;
  for(const format of ["html","pdf"])el(`reports-${format}`).onclick=()=>download(format);
})();
