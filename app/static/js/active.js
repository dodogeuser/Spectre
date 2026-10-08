"use strict";
(() => {
  const el=id=>document.getElementById(id);
  let generation=0,timer=null,data=null,targets=[],finding=null,busy=false,mode="standalone";
  const text=(p,value,tag="p")=>{const n=document.createElement(tag);n.textContent=value;p.append(n);return n;};
  const action=(p,label,fn)=>{const b=document.createElement("button");b.type="button";b.textContent=label;b.onclick=()=>Promise.resolve(fn()).catch(showError);p.append(b);return b;};
  const valid=(id,g)=>selectedCase?.id===id&&g===generation;
  const root=()=>`/api/cases/${selectedCase.id}/active`;
  function clearRequest(){el("active-path").value="";el("active-query").value="{}";el("active-headers").value="{}";el("active-module").value="validation";el("active-method").value="HEAD";el("active-scheme").value="https";el("active-confirm").checked=false;}
  function cancelPreparation(reason){finding=null;mode="cancelled";clearRequest();el("active-verification").textContent=`Prepared finding verification was cancelled: ${reason}. Prepare it again or explicitly start a new standalone request.`;controls();}
  window.resetActive=()=>{generation++;if(timer)clearInterval(timer);timer=null;data=null;targets=[];if(mode!=="standalone")cancelPreparation("case context was reset or reopened");else{finding=null;clearRequest();}el("active-confirm").checked=false;el("active-runs").replaceChildren();el("active-grants").replaceChildren();};
  function controls(){
    const readOnly=user.role==="viewer"||selectedCase?.status==="archived";
    el("active-execute").disabled=mode==="cancelled"||busy||readOnly||!data?.enabled||data.stopped||!el("active-confirm").checked;
    el("active-grant").disabled=busy||readOnly||!data?.enabled||!data.can_authorize||!el("active-confirm").checked;
    el("active-stop").disabled=busy||readOnly||!data;
    el("active-resume").disabled=busy||readOnly||!data?.can_authorize;
  }
  async function refresh(){
    if(!selectedCase)return;
    const id=selectedCase.id,g=generation;
    const result=await api(root());if(!valid(id,g))return;data=result;
    el("active-message").textContent=`${result.enabled?"ACTIVE feature enabled":"PASSIVE mode: active provider disabled by local configuration"} · Case ${result.stopped?"STOPPED":"not stopped"}. Exact host grants only; discovered assets never inherit permission.`;
    el("active-grants").replaceChildren();
    if(!result.authorizations.length)text(el("active-grants"),"No explicit active authorization recorded.");
    for(const grant of result.authorizations){const card=document.createElement("article");text(card,`Authorization #${grant.id} · Target #${grant.target_id} · ${grant.revoked_at?"REVOKED":"CURRENT"}`,"h4");text(card,`${grant.scope_json.host} · ports ${grant.scope_json.ports.join(", ")} · ${grant.granted_at} UTC · User #${grant.granted_by}`);text(card,grant.note);if(!grant.revoked_at&&result.can_authorize&&user.role!=="viewer")action(card,"Revoke authorization",()=>mutate(`/authorizations/${grant.id}`,"DELETE"));el("active-grants").append(card);}
    el("active-runs").replaceChildren();
    if(!result.runs.length)text(el("active-runs"),"No active runs. Viewing this workspace never contacts targets.");
    for(const run of result.runs){const card=document.createElement("article");text(card,`ACTIVE run #${run.id} · ${run.module} v${run.version} · ${run.status}`,"h4");text(card,`Target #${run.target_id} · Authorization #${run.authorization_id} · ${run.requested_at} UTC${run.error_code?" · "+run.error_code:""}`);text(card,JSON.stringify({action:run.action_json,result:run.result_json},null,2),"pre");for(const id of run.evidence_ids)action(card,`Active evidence #${id}`,()=>window.inspectStoredEvidence(id));if(["queued","running"].includes(run.status)&&user.role!=="viewer")action(card,"Cancel run",()=>mutate(`/runs/${run.id}/cancel`,"POST"));el("active-runs").append(card);}
    if(result.has_more)text(el("active-runs"),"Latest 100 runs shown; older history remains stored.");controls();
  }
  async function mutate(path,method,body){await api(root()+path,method,body);await refresh();}
  window.openActive=async()=>{
    const id=selectedCase.id,g=generation;
    const rows=await api(`/api/cases/${id}/targets`);if(!valid(id,g))return;targets=rows;
    const selected=finding?.target_id||Number(el("active-target").value);el("active-target").replaceChildren();
    for(const target of rows.filter(t=>!t.archived&&["domain","url"].includes(t.type))){const option=document.createElement("option");option.value=target.id;option.textContent=`#${target.id} ${target.normalized_value} · ${target.scope_status}`;el("active-target").append(option);}
    if(selected)el("active-target").value=String(selected);
    if(rows.length===100)text(el("active-message"),"Target list bounded to first 100 records.");
    await refresh();if(!valid(id,g))return;if(timer)clearInterval(timer);timer=setInterval(()=>{if(!document.hidden&&!document.querySelector('[data-pane="active"]').hidden&&!busy)refresh().catch(showError);},5000);
  };
  window.openActiveVerification=item=>{
    // Validate before changing form state. Preparation never fetches or executes.
    const fail=()=>{cancelPreparation("finding identity or target/URL data is invalid");throw Error("Cannot prepare verification from this finding's target/URL data. Reload and reopen the finding; no request was sent.");};
    if(busy)throw Error("Wait for the current active request to finish before preparing another verification.");
    if(!selectedCase||item?.case_id!==selectedCase.id||!Number.isInteger(item?.id)||item.id<=0||!Number.isInteger(item?.target_id)||item.target_id<=0||item.target?.id!==item.target_id||typeof item.target.value!=="string"||!item.target.value.trim())fail();
    let targetUrl,affected;
    try{
      targetUrl=new URL(/^https?:\/\//i.test(item.target.value)?item.target.value:`https://${item.target.value}`);
      affected=new URL(item.generated_json?.affected_url);
    }catch{fail();}
    if(!["http:","https:"].includes(targetUrl.protocol)||!["http:","https:"].includes(affected.protocol)||targetUrl.hostname!==affected.hostname||targetUrl.username||targetUrl.password||affected.username||affected.password||targetUrl.port||affected.port)fail();
    if(typeof window.consoleNavigate!=="function"||!document.querySelector('[data-pane="active"]'))throw Error("Active / Validation navigation is unavailable. Reload SPECTRE; no request was sent.");
    if(timer)clearInterval(timer);timer=null;data=null;
    finding=Object.freeze({id:item.id,case_id:item.case_id,target_id:item.target_id,module:"validation",method:"HEAD",scheme:affected.protocol.slice(0,-1),path:affected.pathname||"/"});mode="finding";
    el("active-target").replaceChildren();const option=document.createElement("option");option.value=String(item.target_id);option.textContent=`#${item.target_id} ${item.target.value} · ${item.target.scope_status}`;el("active-target").append(option);el("active-target").value=String(item.target_id);
    el("active-module").value="validation";el("active-method").value="HEAD";
    el("active-scheme").value=affected.protocol.slice(0,-1);el("active-path").value=affected.pathname||"/";
    el("active-query").value="{}";el("active-headers").value="{}";
    el("active-port-80").checked=affected.protocol==="http:";el("active-port-443").checked=affected.protocol==="https:";
    el("active-confirm").checked=false;el("active-grants").replaceChildren();el("active-runs").replaceChildren();
    el("active-verification").textContent=`Prepared Finding #${item.id}. No request sent. Refresh stored active state, confirm authority again, then explicitly execute. Original observation remains unchanged.`;
    el("active-message").textContent="Refresh stored active state before execution. Preparation does not contact the target or check current authorization.";
    controls();window.consoleNavigate("active",{preparedVerification:true});
  };
  el("active-refresh").onclick=()=>refresh().catch(showError);
  el("active-confirm").onchange=controls;
  el("active-target").onchange=()=>{if(mode==="finding"&&finding?.target_id===Number(el("active-target").value))return;if(mode!=="standalone")cancelPreparation("target context changed");else el("active-confirm").checked=false;controls();};
  el("active-standalone").onclick=()=>{if(busy)return;finding=null;mode="standalone";clearRequest();el("active-verification").textContent="Standalone active request. Configure a path and confirm authority; no finding association.";controls();};
  el("active-grant").onclick=async()=>{try{await mutate(`/targets/${el("active-target").value}/authorization`,"POST",{confirmed:el("active-confirm").checked,note:el("active-note").value,ports:ports()});el("active-confirm").checked=false;controls();}catch(error){showError(error);}};
  el("active-stop").onclick=()=>mutate("/control","PUT",{stopped:true,confirmed:true}).catch(showError);
  el("active-resume").onclick=()=>mutate("/control","PUT",{stopped:false,confirmed:el("active-confirm").checked}).catch(showError);
  function ports(){return [80,443].filter(p=>el(`active-port-${p}`).checked);}
  el("active-form").onsubmit=async event=>{
    event.preventDefault();if(busy||!el("active-confirm").checked)return;
    if(mode==="cancelled"){showError(Error("Preparation was cancelled. Prepare the finding again or explicitly start a new standalone request."));return;}
    const prepared=finding;
    const matches=()=>mode==="finding"&&prepared&&finding===prepared&&Number.isInteger(prepared.id)&&prepared.id>0&&prepared.case_id===selectedCase?.id&&prepared.target_id===Number(el("active-target").value)&&["module","method","scheme","path"].every(key=>el(`active-${key}`).value===prepared[key]);
    if(mode==="finding"&&!matches()){cancelPreparation("prepared identity or request fields no longer match");showError(Error("Prepare the finding again; its verification context changed. No request sent."));return;}
    if(finding&&!data){showError(Error("Refresh stored active state before executing this prepared verification."));return;}
    const id=selectedCase.id,g=generation;busy=true;controls();
    try{
      const query=JSON.parse(el("active-query").value||"{}"),headers=JSON.parse(el("active-headers").value||"{}");
      const body={module:el("active-module").value,method:el("active-method").value,scheme:el("active-scheme").value,path:el("active-path").value,query,headers,ports:ports(),confirmed:true};
      if(mode==="finding"){
        if(Object.keys(query).length||Object.keys(headers).length){cancelPreparation("query or custom headers changed");throw Error("Prepare the finding again without query/custom headers. No request sent.");}
        const current=await api(`/api/cases/${id}/findings/${prepared.id}`);
        if(!valid(id,g)||!matches()||!el("active-confirm").checked||current.id!==prepared.id||current.case_id!==prepared.case_id||current.target_id!==prepared.target_id){cancelPreparation("finding/case/target identity or confirmation no longer matches");throw Error("Prepare the finding again; its identity changed. No active request sent.");}
        body.finding_id=prepared.id;
      }
      await api(root()+`/targets/${el("active-target").value}/runs`,"POST",body);
      if(valid(id,g)){el("active-confirm").checked=false;await refresh();}
    }catch(error){if(mode==="finding")cancelPreparation("verification submission failed; prepare it again");showError(error);}finally{busy=false;controls();}
  };
})();
