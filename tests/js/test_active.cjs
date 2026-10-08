/* Shipped active handlers, inert DOM, deterministic APIs; no network. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
module.exports=async function run(){
  class Element{
    constructor(){this.children=[];this.value='';this.checked=false;this.hidden=false;this._text='';}
    set textContent(v){this._text=String(v);this.children=[];}get textContent(){return this._text;}
    append(...v){this.children.push(...v);}replaceChildren(...v){this.children=v;}
    set innerHTML(v){throw Error('Unsafe HTML');}
  }
  const ids=new Map(),calls=[],intervals=[],errors=[];ids.set('active-standalone',new Element());
  for(const id of ['active-confirm','active-verification','active-runs','active-grants','active-execute','active-grant','active-stop','active-resume','active-message','active-target','active-module','active-method','active-path','active-refresh','active-note','active-port-80','active-port-443','active-form','active-query','active-headers','active-scheme'])ids.set(id,new Element());
  ids.get('active-port-443').checked=true;ids.get('active-module').value='http';ids.get('active-method').value='HEAD';ids.get('active-scheme').value='https';ids.get('active-path').value='/';ids.get('active-target').value='24';
  let enabled=false,pending=null;
  const overview=()=>({enabled,stopped:false,can_authorize:true,authorizations:[],runs:[],has_more:false});
  const context={window:{},selectedCase:{id:12,status:'open'},user:{role:'investigator'},document:{hidden:false,getElementById:id=>ids.get(id),createElement:()=>new Element(),querySelector:()=>({hidden:false})},URL,JSON,Number,setInterval(fn,ms){intervals.push({fn,ms});return fn;},clearInterval(){},showError(e){errors.push(e.message);},async api(url,method='GET',body){calls.push({url,method,body});if(pending){const p=pending;pending=null;return await p;}if(url.endsWith('/targets'))return[{id:24,type:'domain',normalized_value:'example.com',scope_status:'active_authorized'}];return overview();}};
  context.window.consoleNavigate=()=>{};
  vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../../app/static/js/active.js'),'utf8'),context);
  await context.window.openActive();assert.ok(calls.every(c=>c.method==='GET'));
  assert.equal(ids.get('active-execute').disabled,true);assert.equal(intervals[0].ms,5000);
  enabled=true;await ids.get('active-refresh').onclick();ids.get('active-confirm').checked=true;ids.get('active-confirm').onchange();assert.equal(ids.get('active-execute').disabled,false);
  await ids.get('active-form').onsubmit({preventDefault(){}});
  const request=calls.find(c=>c.method==='POST');assert.ok(request.url.endsWith('/targets/24/runs'));assert.equal(request.body.confirmed,true);assert.equal(request.body.method,'HEAD');assert.equal(ids.get('active-confirm').checked,false);
  context.user.role='viewer';await ids.get('active-refresh').onclick();assert.equal(ids.get('active-execute').disabled,true);assert.equal(ids.get('active-grant').disabled,true);
  let resolve;pending=new Promise(r=>resolve=r);const old=ids.get('active-refresh').onclick();context.selectedCase={id:99};context.window.resetActive();resolve({...overview(),authorizations:[{id:1,note:'Other case private'}]});await old;assert.equal(ids.get('active-grants').children.length,0);
  assert.ok(calls.every(c=>!c.url.includes('/collectors/')&&!c.url.includes('/ai/')));
  context.selectedCase={id:12,status:'open'};
  const finding={id:7,case_id:12,target_id:24,target:{id:24,value:'example.com',scope_status:'active_authorized'},generated_json:{affected_url:'https://example.com/'}};
  const beforePrepare=calls.length;
  for(const invalid of [
    {...finding,case_id:99},
    {...finding,target:{...finding.target,id:99}},
    {...finding,target:{...finding.target,value:null}},
    {...finding,generated_json:{affected_url:'https://evil.example/'}},
    {...finding,generated_json:{affected_url:'javascript:alert(1)'}},
    {...finding,generated_json:{affected_url:'https://example.com:8443/'}}
  ])assert.throws(()=>context.window.openActiveVerification(invalid),/Cannot prepare verification/);
  assert.equal(calls.length,beforePrepare,'Invalid preparation never fetches or executes');
  return{passed:true,read_only_navigation:true,explicit_confirmation:true,default_disabled:true,viewer_controls:true,case_isolation:true,bounded_polling:true,no_passive_collector_or_ai_calls:true};
};
