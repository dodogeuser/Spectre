/* Actual report handlers: explicit downloads, CSRF, safe DOM and stale-case guards. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
module.exports=async function run(){
  class Element{
    constructor(){this.children=[];this.checked=true;this.disabled=false;this._text='';}
    set textContent(v){this._text=String(v);this.children=[];}get textContent(){return this._text;}
    append(...v){this.children.push(...v);}replaceChildren(...v){this.children=v;}remove(){}click(){downloads.push(this.download);}
    set innerHTML(v){throw Error('Unsafe HTML');}
  }
  const ids=new Map(),downloads=[],calls=[],timeouts=[],urls=[];
  for(const id of ['reports-refresh','reports-redact','reports-html','reports-pdf','reports-status','reports-preview'])ids.set(id,new Element());
  let pending=null,fail=null,canExport=true;
  const context={window:{},selectedCase:{id:15},user:{csrf_token:'test-csrf'},document:{body:new Element(),getElementById:id=>ids.get(id),createElement:()=>new Element()},URL:{createObjectURL(){urls.push('created');return'blob:test';},revokeObjectURL(){urls.push('revoked');}},setTimeout(fn){timeouts.push(fn);},async api(url){
    calls.push({url,method:'GET'});if(pending){const value=pending;pending=null;return await value;}if(fail)throw Error(fail);
    return {case:{id:context.selectedCase.id,title:'<script>inert</script>',status:'open',owner:'researcher',description:'Stored case',created_at:'2026-10-06'},counts:{targets:1,evidence:9},report_version:'1.0.0',snapshot_sha256:'a'.repeat(64),limitations:'Missing is not negative',can_export:canExport};
  },async fetch(url,options){calls.push({url,...options});if(pending){const value=pending;pending=null;return await value;}return{ok:!fail,json:async()=>({detail:fail}),blob:async()=>({type:'application/pdf'})};}};
  vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../../app/static/js/reports.js'),'utf8'),context);
  context.window.resetReports();assert.equal(ids.get('reports-pdf').disabled,true);
  await context.window.openReports();assert.equal(ids.get('reports-pdf').disabled,false);assert.equal(downloads.length,0);
  assert.equal(ids.get('reports-preview').children[0].textContent,'Case #15: <script>inert</script>');
  await ids.get('reports-pdf').onclick();assert.deepEqual(downloads,['spectre-case-15.pdf']);
  const request=calls.find(c=>c.method==='POST');assert.equal(request.headers['X-CSRF-Token'],'test-csrf');assert.equal(request.credentials,'same-origin');assert.deepEqual(JSON.parse(request.body),{format:'pdf',redact_notes:true});
  timeouts.forEach(fn=>fn());assert.deepEqual(urls,['created','revoked']);
  ids.get('reports-redact').checked=false;await ids.get('reports-redact').onchange();assert.ok(calls.at(-1).url.endsWith('redact_notes=false'));
  fail='Provider not needed; simulated render error';await ids.get('reports-html').onclick();assert.match(ids.get('reports-status').textContent,/simulated render error/);assert.equal(downloads.length,1);fail=null;
  let resolve;pending=new Promise(r=>resolve=r);const old=context.window.openReports();context.selectedCase={id:16};context.window.resetReports();resolve({case:{id:15,title:'Old private case'}});await old;
  assert.equal(ids.get('reports-preview').children.length,0,'Old preview cannot leak into the next case');
  await context.window.openReports();pending=new Promise(r=>resolve=r);const oldDownload=ids.get('reports-html').onclick();context.selectedCase={id:17};context.window.resetReports();resolve({ok:true,blob:async()=>({})});await oldDownload;assert.equal(downloads.length,1,'Old case export response is discarded');
  canExport=false;await context.window.openReports();assert.equal(ids.get('reports-pdf').disabled,true);await ids.get('reports-pdf').onclick();assert.equal(downloads.length,1);
  assert.match(ids.get('reports-status').textContent,/Viewer access is read-only/);
  assert.ok(calls.every(c=>c.url.includes('/reports/')),'No collector or AI route is called');
  return {passed:true,preview_navigation:true,explicit_download_csrf:true,safe_text:true,redaction_option:true,errors:true,stale_case_discarded:true,viewer_read_only:true,no_collection_or_ai:true};
};
