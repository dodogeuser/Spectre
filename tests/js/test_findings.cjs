/* Inert DOM exercise of actual findings handlers; only explicit generate/review can mutate. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
module.exports=async function run(){
  class Element{constructor(tag='div'){this.tag=tag;this.children=[];this.value='';this.textContent='';}append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}set innerHTML(value){throw Error('No HTML injection');}}
  const ids=new Map(),document={getElementById(id){if(!ids.has(id))ids.set(id,new Element());return ids.get(id);},createElement(tag){return new Element(tag);}};
  for(const m of fs.readFileSync(path.join(__dirname,'../../app/static/index.html'),'utf8').matchAll(/id="([^"]+)"/g))document.getElementById(m[1]);
  const score={severity:'informational',confidence:.95,priority:'informational',rule_state:'observed',assessment_state:'observed',affected_url:'https://example.com/',why:['Recorded header absence only; not a vulnerability.'],recency:{category:'recent',age_days:0,reference_captured_at:'2026-10-06T00:00:00'}};
  const finding={id:1,case_id:12,title:'Missing header',description:'Informational observation',finding_type:'missing_security_header',rule_id:'web.missing_header.content-security-policy',rule_version:'1.0.0',severity:'informational',confidence:.95,status:'informational',generated_json:score,original_json:score,entity_id:null,target_id:24,target:{id:24,value:'example.com',scope_status:'passive_allowed',archived:false},created_at:'2026-10-06T00:00:00',updated_at:'2026-10-06T00:00:00',notes:'',severity_override:null,override_reason:'',evidence:[{id:61,source_type:'web_metadata',captured_at:'2026-10-06T00:00:00',active_support:true,assessment_support:true}],relationships:[],revisions:[]};
  const requests=[],context={document,window:{},selectedCase:{id:12,status:'open'},user:{role:'investigator'},URLSearchParams,Promise,console,showError(error){throw error;},async api(url,method='GET',body){requests.push({url,method,body});assert.match(url,/^\/api\/cases\/12\//);assert.ok(!url.includes('/collectors/'));
    if(url.includes('/findings/generate')){assert.equal(method,'POST');return {created:1,updated:0,unchanged:0,skipped:[],has_more:false};}
    if(url.includes('/findings/1')){if(method==='PATCH'){Object.assign(finding,body);finding.severity=body.severity_override||'informational';}return finding;}
    if(url.includes('/findings?'))return {findings:[finding],has_more:false};
    if(url.includes('/evidence/61'))return {id:61,run_id:35,source_type:'web_metadata',source_ref:'https://example.com/',captured_at:'2026-10-06T00:00:00',sha256:'a'.repeat(64),parsed_json:{title:'<script>inert</script>'},raw_json:{fixture:true}};
    if(url.endsWith('/audit'))return [];throw Error('Unexpected API request');}};
  vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../../app/static/js/findings.js'),'utf8'),context);
  context.window.configureFindings();assert.equal(ids.get('findings-generate').disabled,false);
  await ids.get('findings-load').onclick();assert.ok(requests.every(r=>r.method==='GET'));
  const card=ids.get('findings-list').children[0];await card.children.find(n=>n.tag==='button').onclick();
  assert.ok(ids.get('finding-detail').children.some(n=>n.textContent==='Why this finding / rubric'));
  assert.ok(ids.get('finding-detail').children.some(n=>n.tag==='pre'&&n.textContent.includes('informational')));
  await ids.get('finding-detail').children.find(n=>n.tag==='button'&&n.textContent==='Inspect evidence #61').onclick();
  assert.ok(ids.get('finding-evidence').children.some(n=>n.tag==='pre'&&n.textContent.includes('<script>inert</script>')));
  const form=ids.get('finding-detail').children.find(n=>n.tag==='form');
  const selects=form.children.filter(n=>n.tag==='label').map(n=>n.children[0]);selects[0].value='accepted';selects[1].value='high';selects[2].value='Review note';selects[3].value='Explicit analyst reason';
  await form.onsubmit({preventDefault(){}});assert.equal(finding.confidence,.95);assert.equal(finding.original_json.severity,'informational');
  await ids.get('findings-generate').onclick();assert.equal(requests.filter(r=>r.method==='POST').length,1);
  context.user.role='viewer';context.window.configureFindings();assert.equal(ids.get('findings-generate').disabled,true);
  context.window.resetFindings();assert.equal(ids.get('findings-controls').hidden,true);
  return {passed:true,inert_evidence:true,reasoning_visible:true,severity_confidence_independent:true,explicit_generate_only:true,no_collector_requests:true,requests:requests.length};
};
