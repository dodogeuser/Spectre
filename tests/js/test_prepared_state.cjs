/* Actual Finding/Active handlers; all API calls are inert, or the fixture bridge. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
async function exercise(finding,transition='refresh',submitHook,authorizationHook){
  class Element{constructor(tag='div'){this.tag=tag;this.value='';this.checked=false;this.children=[];this.textContent='';}append(...n){this.children.push(...n);}replaceChildren(...n){this.children=n;}scrollIntoView(){}}
  const nodes=new Map(),calls=[],errors=[];for(const m of fs.readFileSync(path.join(__dirname,'../../app/static/index.html'),'utf8').matchAll(/id="([^"]+)"/g))nodes.set(m[1],new Element());
  const context={window:{consoleNavigate(){}},document:{getElementById:id=>nodes.get(id),createElement:tag=>new Element(tag),querySelector:()=>({hidden:false})},selectedCase:{id:finding.case_id,status:'open'},user:{role:'investigator'},URL,URLSearchParams,JSON,Number,Promise,setInterval(){return 1},clearInterval(){},showError(e){errors.push(e.message)},async api(url,method='GET',body){calls.push({url,method,body});if(method==='POST'&&url.endsWith('/runs'))return submitHook?await submitHook(body):{};if(method==='POST'&&url.endsWith('/authorization')&&authorizationHook)return await authorizationHook(body);if(url.includes('/findings/'))return finding;if(url.endsWith('/targets'))return [{id:finding.target_id,type:'domain',normalized_value:finding.target.value,scope_status:'active_authorized'}];return {enabled:true,stopped:false,can_authorize:true,authorizations:[],runs:[]};}};
  vm.createContext(context);for(const file of ['findings','active']){
    let source=fs.readFileSync(path.join(__dirname,`../../app/static/js/${file}.js`),'utf8');
    // Test-only fault injection into private state; no production test hook.
    if(file==='active'&&transition==='missing')source=source.replace('  const text=', '  window.corruptPreparedForTest=()=>{finding=null;};\n  const text=');
    vm.runInContext(source,context);
  }
  await context.window.inspectStoredFinding(finding.id);
  await nodes.get('finding-detail').children.find(n=>n.textContent==='Prepare authorized verification').onclick();
  assert.equal(calls.filter(c=>c.method==='POST').length,0);
  await nodes.get('active-refresh').onclick();
  if(transition==='same-target')nodes.get('active-target').onchange();
  if(transition==='authorization'){nodes.get('active-confirm').checked=true;await nodes.get('active-grant').onclick();assert.equal(nodes.get('active-confirm').checked,false);}
  if(transition==='target'){nodes.get('active-target').value='999';nodes.get('active-target').onchange();}
  if(transition==='reset')context.window.resetActive();
  if(transition==='case'){context.selectedCase={id:999,status:'open'};context.window.resetActive();}
  if(transition==='method')nodes.get('active-method').value='GET';
  if(transition==='identity')finding={...finding,id:finding.id+1};
  if(transition==='missing')context.window.corruptPreparedForTest();
  if(['target','reset','case'].includes(transition)){assert.equal(nodes.get('active-confirm').checked,false);assert.equal(nodes.get('active-path').value,'');assert.equal(nodes.get('active-execute').disabled,true);assert.match(nodes.get('active-verification').textContent,/cancelled/);}
  nodes.get('active-confirm').checked=true;
  await nodes.get('active-form').onsubmit({preventDefault(){}});
  const posts=calls.filter(c=>c.method==='POST'&&c.url.endsWith('/runs'));
  if(['target','reset','case','method','identity','missing'].includes(transition)){assert.equal(posts.length,0);assert.ok(errors.length);assert.match(nodes.get('active-verification').textContent,/cancelled/);}
  else{assert.equal(posts.length,1);assert.equal(posts[0].body.finding_id,finding.id);}
  return {nodes,calls,context,posts};
}
function fixture(){return {id:7,case_id:16,target_id:27,target:{id:27,value:'example.com',scope_status:'active_authorized'},title:'Header observation',description:'Stored only',rule_id:'web.missing_header.strict-transport-security',rule_version:'1',severity:'informational',confidence:.95,generated_json:{affected_url:'https://example.com/login',why:[],evidence_ids:[]},original_json:{},evidence:[],relationships:[],revisions:[]};}
module.exports=async()=>{
  for(const transition of ['refresh','same-target','authorization','target','reset','case','method','identity','missing'])await exercise(fixture(),transition);
  const cancelled=await exercise(fixture(),'target');cancelled.nodes.get('active-standalone').onclick();assert.equal(cancelled.nodes.get('active-confirm').checked,false);cancelled.nodes.get('active-path').value='/';await cancelled.nodes.get('active-refresh').onclick();cancelled.nodes.get('active-confirm').checked=true;await cancelled.nodes.get('active-form').onsubmit({preventDefault(){}});assert.equal(cancelled.calls.filter(c=>c.method==='POST'&&c.url.endsWith('/runs')).at(-1).body.finding_id,undefined);
  return {passed:true,transitions:9,standalone_explicit:true,no_silent_fallback:true};
};
module.exports.exercise=exercise;
