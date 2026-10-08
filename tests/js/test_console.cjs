/* Full shipped frontend handlers, real Cytoscape, inert DOM and authorized API fixtures. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const cytoscape=require('../../app/static/vendor/cytoscape.min.js');
module.exports=async function run(){
  class Element{
    constructor(tag='div'){this.tag=tag;this.children=[];this.dataset={};this.attributes={};this.value='';this.hidden=false;this._text='';}
    append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;this._text='';}
    get childNodes(){return this.children;}
    set textContent(value){this._text=String(value);this.children=[];}get textContent(){return this._text;}
    setAttribute(key,value){this.attributes[key]=value;}getAttribute(key){return this.attributes[key];}
    showModal(){this.open=true;}close(){this.open=false;}reset(){}focus(){}
    set innerHTML(value){throw Error('No untrusted HTML');}
  }
  const ids=new Map(),panes=[],navs=[],go=[];
  const html=fs.readFileSync(path.join(__dirname,'../../app/static/index.html'),'utf8');
  const document={hidden:false,getElementById(id){assert.ok(ids.has(id),'Actual HTML must contain '+id);return ids.get(id);},createElement(tag){return new Element(tag);},createTextNode(value){const n=new Element('text');n.textContent=value;return n;},querySelectorAll(selector){return selector==='[data-pane]'?panes:selector==='[data-nav]'?navs:selector==='[data-go]'?go:[];},querySelector(selector){const name=/data-pane="([^"]+)"/.exec(selector)?.[1];return panes.find(p=>p.dataset.pane===name)||null;}};
  for(const m of html.matchAll(/<([a-z][a-z0-9-]*)\b([^>]*?)>/gi)){
    const node=new Element(m[1]),attrs=m[2];for(const a of attrs.matchAll(/([\w-]+)="([^"]*)"/g)){node.setAttribute(a[1],a[2]);if(a[1].startsWith('data-'))node.dataset[a[1].slice(5)]=a[2];if(a[1]==='id'){assert.ok(!ids.has(a[2]),'No duplicate DOM IDs');ids.set(a[2],node);}if(a[1]==='value')node.value=a[2];}
    node.hidden=/\bhidden\b/.test(attrs);if(node.dataset.pane)panes.push(node);if(node.dataset.nav)navs.push(node);if(node.dataset.go)go.push(node);
  }
  const raw={synthetic:true,html:'<script>inert evidence</script>'},hash=crypto.createHash('sha256').update(JSON.stringify({html:raw.html,synthetic:true})).digest('hex');
  let graph={case_id:7,truncated:false,entities:[{id:1,type:'domain',value:'example.com',roles:[],attributes:{},evidence_ids:[15],sources:['dns']},{id:2,type:'ip',value:'8.8.8.8',roles:[],attributes:{},evidence_ids:[15],sources:['dns']},{id:3,type:'url',value:'https://example.com/',roles:[],attributes:{},evidence_ids:[],sources:[]}],relationships:[{from:1,to:2,type:'resolves_to',classification:'observed',confidence:.95,rule:'DNS A/AAAA answer',evidence_ids:[15],support_ids:[12],sources:['dns'],first_seen:'2026-10-06T00:00:00',last_seen:'2026-10-06T00:00:00'}],evidence:[{id:15,target_id:1,run_id:9,source_type:'dns',source_ref:'fixture://stored',collector:'dns',version:'1.0.0',captured_at:'2026-10-06T00:00:00',sha256:hash}]};
  const timeline={offset:0,events:[{timestamp:'2026-10-06T00:00:00',type:'evidence.captured',source:'dns',source_ref:'fixture://stored',key:'evidence:15',evidence_ids:[15],run_ids:[9],entity_ids:[]}],bounded_total:2,has_more:false,truncated:false};
  const finding={id:6,title:'Stored informational finding',description:'Observation only.',entity_id:1,target_id:1,severity:'informational',confidence:.95,status:'informational',rule_id:'web.missing_header.permissions-policy',rule_version:'1.0.0',generated_json:{rule_state:'observed',affected_url:'https://example.com/',evidence_ids:[15]}};
  Object.assign(finding,{case_id:7,target:{id:1,value:'example.com',scope_status:'active_authorized',archived:false},finding_type:'missing_security_header',original_json:{severity:'informational'},evidence:[],relationships:[],revisions:[],created_at:'2026-10-06T00:00:00',updated_at:'2026-10-06T00:00:00'});finding.generated_json.why=['Stored header observation'];
  let explicitSubmit=false,pending=null,clock=Date.now(),lastCy;class TestDate extends Date{static now(){return clock;}}
  const intervals=[],timeouts=[],requests=[],context={document,window:{matchMedia(query){return{matches:query.includes('reduced-motion')};},crypto:crypto.webcrypto},console,Set,Map,Date:TestDate,Number,JSON,TextEncoder,Uint8Array,URL,URLSearchParams,AbortSignal,Promise,location:{reload(){throw Error('No full-page graph refresh');}},setInterval(fn,ms){const t={fn,ms};intervals.push(t);return t;},clearInterval(t){t.cleared=true;},setTimeout(fn,ms){const t={fn,ms};timeouts.push(t);return t;},clearTimeout(t){t.cleared=true;},
    cytoscape(options){lastCy=cytoscape({...options,container:undefined,headless:true,styleEnabled:true});return lastCy;},async fetch(url,options={}){
      const method=options.method||'GET';requests.push({url,method,headers:options.headers,body:options.body});if(method!=='GET')assert.ok(explicitSubmit&&method==='POST'&&url==='/api/cases/7/active/targets/1/runs','Only confirmed fixture execution may mutate');
      const empty=url.includes('/14/');let data;
      if(url==='/health')data={status:'ok'};
      else if(url==='/api/auth/me')data={id:2,username:'researcher',role:'investigator',csrf_token:'test-only'};
      else if(url==='/api/cases?offset=0')data=[{id:7,title:'Graph investigation',status:'open'}];
      else if(/^\/api\/cases\/(7|14)$/.test(url))data={id:empty?14:Number(url.split('/').pop()),title:empty?'Empty':'Graph investigation',status:'open',owner_id:2,description:'Stored case'};
      else if(url.includes('/targets?'))data=empty?[]:[{id:1,type:'domain',value:'example.com',normalized_value:'example.com',scope_status:'passive_allowed',archived:false,created_at:'2026-10-06T00:00:00',updated_at:'2026-10-06T00:00:00'}];
      else if(url.endsWith('/audit'))data=[];
      else if(url.includes('/reports/preview'))data={case:{id:empty?14:7,title:empty?'Empty':'Graph investigation',status:'open',owner:'researcher',created_at:'2026-10-06'},counts:{targets:empty?0:1},report_version:'1.0.0',snapshot_sha256:'a'.repeat(64),limitations:'Stored data only',can_export:true};
      else if(url.includes('/findings/6'))data=finding;
      else if(url.includes('/findings'))data={findings:empty?[]:[finding],has_more:false};
      else if(url.endsWith('/active'))data={enabled:true,stopped:false,can_authorize:true,authorizations:[],runs:[],has_more:false};
      else if(url.endsWith('/collectors'))data=[{name:'dns',version:'1.0.0',enabled:true,supported_types:['domain']},{name:'web_metadata',version:'1.0.0',enabled:true,supported_types:['url']}];
      else if(url.endsWith('/targets/1/domain'))data={domain:'example.com',scope_status:'passive_allowed',limits:'Public sources only.',observations:[],entities:[],relationships:[],runs:[]};
      else if(url.endsWith('/investigation')){if(pending&&!empty){const wait=pending;pending=null;data=await wait;}else data=empty?{case_id:14,entities:[],relationships:[],evidence:[],truncated:false}:graph;}
      else if(url.includes('/timeline?'))data=empty?{offset:0,events:[],bounded_total:0,has_more:false,truncated:false}:timeline;
      else if(url.includes('/entities/1/detail'))data={entity:graph.entities[0],relationships:graph.relationships,evidence:graph.evidence,first_seen:'2026-10-06T00:00:00',last_seen:'2026-10-06T00:00:00',has_more:false};
      else if(url.includes('/evidence/15'))data={id:15,run_id:9,source_type:'dns',source_ref:'fixture://stored',captured_at:'2026-10-06T00:00:00',sha256:hash,raw_json:raw,parsed_json:{synthetic:true}};
      else if(url.endsWith('/runs'))data=[];
      else throw Error('Unexpected API '+url);
      return{ok:true,status:200,async json(){return JSON.parse(JSON.stringify(data));}};
    }};
  vm.createContext(context);
  for(const file of ['main','investigation','findings','ai','reports','active','console'])vm.runInContext(fs.readFileSync(path.join(__dirname,`../../app/static/js/${file}.js`),'utf8'),context);
  const flush=()=>new Promise(r=>setImmediate(r));await flush();await flush();
  let loadedTargets;const targetHook=context.window.updateInvestigationTargets;context.window.updateInvestigationTargets=(rows,offset)=>{loadedTargets=rows;return targetHook(rows,offset);};
  assert.equal(ids.get('auth-panel').hidden,true);assert.equal(ids.get('case-library').open,true);assert.equal(ids.get('local-indicator').textContent,'● LOCAL');
  await vm.runInContext('openCase(7)',context);
  assert.equal(navs.find(n=>n.dataset.nav==='graph').getAttribute('aria-current'),'page');assert.equal(lastCy.nodes().length,3);
  assert.equal(ids.get('inspector-shell').hidden,true,'Inspector begins closed');
  assert.ok(loadedTargets?.length,'Target presentation hook receives authorized targets');
  assert.ok(ids.get('targets').children.length,'Targets loaded through real case handler');
  assert.match(ids.get('targets').children[0].children[0].textContent,/example.com/);
  assert.equal(lastCy.nodes().filter(n=>n.data('root')===1).length,1,'Canonical domain root reuses stored entity: '+JSON.stringify(lastCy.nodes().map(n=>n.data()))+' '+ids.get('message').textContent);
  assert.equal(lastCy.getElementById('t1').length,0,'No duplicate target marker');
  assert.match(ids.get('current-case').textContent,/#7/);assert.equal(ids.get('nav-evidence-count').textContent,'1');
  lastCy.getElementById('n1').emit('tap');await flush();
  assert.ok(ids.get('graph-detail').children.some(n=>n.textContent==='example.com'));assert.ok(lastCy.getElementById('n3').hasClass('muted'));
  assert.equal(ids.get('inspector-shell').hidden,false);lastCy.emit('tap');assert.equal(lastCy.elements('.muted').length,0,'Background clears emphasis');assert.equal(ids.get('inspector-shell').hidden,true);
  lastCy.edges()[0].emit('tap');assert.ok(ids.get('graph-detail').children.some(n=>n.textContent==='DNS A/AAAA answer'));assert.ok(ids.get('graph-detail').children.some(n=>n.textContent.includes('#12')));
  const evidenceButton=ids.get('graph-detail').children.find(n=>n.tag==='button');await evidenceButton.onclick();
  assert.ok(ids.get('graph-detail').children.some(n=>n.tag==='pre'&&n.textContent.includes('<script>inert evidence</script>')));
  await ids.get('graph-detail').children.find(n=>n.textContent==='Verify raw evidence hash').onclick();assert.ok(ids.get('graph-detail').children.some(n=>n.textContent==='Verified · raw SHA-256 matches'));
  for(const name of ['targets','timeline','evidence','findings','overview','settings','reports']){navs.find(n=>n.dataset.nav===name).onclick();await flush();assert.equal(panes.find(p=>p.dataset.pane===name).hidden,false);}
  assert.equal(ids.get('evidence-list').children.length,1);assert.equal(ids.get('findings-list').children.length,1);assert.equal(ids.get('timeline-events').children.length,1);assert.match(ids.get('activity-feed').textContent,/Evidence #15/);
  context.window.consoleNavigate('collectors');await flush();await ids.get('collector-targets').children[0].onclick();
  const collectorCards=ids.get('collector-registry').children;
  assert.equal(collectorCards[0].children[0].textContent,'DNS records');assert.ok(collectorCards[0].children.some(n=>n.textContent==='Applicable'));
  assert.ok(collectorCards[1].children.some(n=>n.textContent==='Not applicable'),'Domain does not gain URL-only web capability');assert.equal(collectorCards[1].children.find(n=>n.tag==='button').disabled,true);
  assert.equal(ids.get('domain-actions').children.length,1,'Existing explicit DNS collection control remains available');
  assert.equal(ids.get('message').textContent,'','Opening actual collection controls succeeds without collection');
  context.window.consoleNavigate('graph');const original=lastCy,nodePosition={...lastCy.getElementById('n1').position()};
  graph=JSON.parse(JSON.stringify(graph));graph.entities.push({id:4,type:'asn',value:'AS15133',roles:[],attributes:{},evidence_ids:[15],sources:['dns']});graph.relationships.push({...graph.relationships[0],from:2,to:4,type:'announced_by',classification:'derived',support_ids:[13]});
  const polling=intervals.find(t=>t.ms===12000);await polling.fn();assert.equal(lastCy,original,'Incremental update keeps Cytoscape instance');assert.equal(lastCy.nodes().length,4);assert.ok(lastCy.getElementById('n4').hasClass('new-discovery'));assert.equal(lastCy.getElementById('n1').position('x'),nodePosition.x);assert.equal(lastCy.getElementById('n1').position('y'),nodePosition.y);
  assert.equal(lastCy.getElementById('n1').hasClass('new-discovery'),false);assert.ok(timeouts.some(t=>t.ms===1600));clock+=1700;for(const t of timeouts)if(!t.cleared)t.fn();
  assert.equal(lastCy.getElementById('e:2:4:announced_by').style('line-style'),'dashed');
  await polling.fn();assert.equal(lastCy.getElementById('n4').hasClass('new-discovery'),false,'Unchanged nodes must not animate again');assert.equal(lastCy.edges().length,2);
  const withNewNode=JSON.parse(JSON.stringify(graph));graph={...graph,entities:graph.entities.filter(n=>n.id!==4),relationships:graph.relationships.filter(e=>e.to!==4)};await polling.fn();graph=withNewNode;await polling.fn();assert.equal(lastCy.getElementById('n4').hasClass('new-discovery'),false,'A previously seen ID reappearing is not a new discovery');
  await vm.runInContext('openCase(7)',context);assert.equal(lastCy.elements('.new-discovery').length,0,'Reloading existing records does not highlight them');
  let resolve;pending=new Promise(r=>resolve=r);const oldPoll=polling.fn();await flush();await vm.runInContext('openCase(14)',context);resolve(graph);await oldPoll;
  assert.equal(lastCy.nodes().length,0);assert.match(ids.get('current-case').textContent,/#14/);assert.equal(ids.get('nav-targets-count').textContent,'');assert.match(ids.get('activity-feed').textContent,/No stored activity/);
  assert.equal(ids.get('graph-empty-title').textContent,'No targets added to this case yet');assert.equal(ids.get('graph-empty-action').textContent,'Add a target');
  const targetOnly={id:25,type:'domain',value:'example.org',normalized_value:'example.org',scope_status:'passive_allowed',archived:false,created_at:'2026-10-06T00:00:00',updated_at:'2026-10-06T00:00:00'};
  context.window.consoleTargets([targetOnly],0);assert.equal(lastCy.nodes().length,1);assert.equal(lastCy.edges().length,0,'A target marker invents no relationships');assert.equal(lastCy.getElementById('t25').data('entityId'),undefined);
  assert.equal(ids.get('graph-empty-title').textContent,'No infrastructure discovered yet');lastCy.getElementById('t25').emit('tap');await flush();assert.ok(ids.get('graph-detail').children.some(n=>n.textContent==='example.org'));
  context.window.updateInvestigationSnapshot({case_id:14,entities:[{id:50,type:'domain',value:'example.org',roles:[],attributes:{},evidence_ids:[],sources:[]}],relationships:[],evidence:[],truncated:false});
  assert.equal(lastCy.nodes().length,1,'Stored entity replaces its standalone target marker');assert.equal(lastCy.getElementById('t25').length,0);assert.equal(lastCy.getElementById('n50').data('root'),1);assert.equal(lastCy.edges().length,0);
  context.window.consoleTargets([{...targetOnly,archived:true}],0);assert.equal(lastCy.getElementById('n50').data('root'),0,'Archive does not erase a historical stored entity');
  context.window.updateInvestigationSnapshot({case_id:14,entities:[],relationships:[],evidence:[],truncated:false});context.window.consoleTargets([targetOnly],0);
  context.window.consoleTargets([{...targetOnly,archived:true}],0);assert.equal(lastCy.nodes().length,0,'Archived standalone root disappears');context.window.consoleTargets([],0);
  for(const name of ['evidence','findings','timeline','collectors']){context.window.consoleNavigate(name);await flush();}
  assert.equal(ids.get('evidence-list').children.length,0);assert.match(ids.get('collector-runs').children[0].textContent,/No stored runs/);
  assert.match(ids.get('findings-list').children[0].textContent,/No stored findings/);assert.equal(ids.get('timeline-events').children[0].children[0].textContent,'Go to targets');
  context.window.resetInvestigation();assert.ok(requests.every(r=>r.method==='GET'));assert.ok(!requests.some(r=>r.url.includes('/collectors/')&&r.url.includes('/runs')));
  // Real Finding -> Active navigation with the complete shipped script combination.
  await vm.runInContext('openCase(7)',context);await context.window.inspectStoredFinding(6);
  const prepare=()=>ids.get('finding-detail').children.find(n=>n.textContent==='Prepare authorized verification').onclick();
  const handler=context.window.openActiveVerification;
  delete context.window.openActiveVerification;await prepare();assert.match(ids.get('message').textContent,/unavailable.*Reload/);context.window.openActiveVerification=handler;
  finding.target.value='';await context.window.inspectStoredFinding(6);await prepare();assert.match(ids.get('message').textContent,/target\/URL data.*Reload/);
  finding.target.value='example.com';await context.window.inspectStoredFinding(6);await prepare();assert.equal(ids.get('active-path').value,'/');assert.equal(ids.get('active-scheme').value,'https');
  finding.target.value='example.com';finding.generated_json.affected_url='https://example.com/login';await context.window.inspectStoredFinding(6);
  ids.get('active-target').value='999';ids.get('active-module').value='manual';ids.get('active-method').value='OPTIONS';ids.get('active-scheme').value='http';ids.get('active-path').value='/old';ids.get('active-query').value='{"old":"value"}';ids.get('active-headers').value='{"Accept":"text/plain"}';ids.get('active-confirm').checked=true;
  const before=requests.length;await prepare();await flush();assert.equal(requests.length,before,'Preparation makes no network request, including GET');
  assert.equal(panes.find(p=>p.dataset.pane==='active').hidden,false);assert.equal(ids.get('active-target').value,'1');assert.equal(ids.get('active-module').value,'validation');assert.equal(ids.get('active-method').value,'HEAD');assert.equal(ids.get('active-scheme').value,'https');assert.equal(ids.get('active-path').value,'/login');assert.equal(ids.get('active-query').value,'{}');assert.equal(ids.get('active-headers').value,'{}');assert.equal(ids.get('active-confirm').checked,false);assert.equal(ids.get('active-execute').disabled,true);assert.match(ids.get('active-verification').textContent,/Finding #6/);
  await ids.get('active-form').onsubmit({preventDefault(){}});assert.equal(requests.length,before,'Fresh confirmation mandatory');
  ids.get('active-confirm').checked=true;await ids.get('active-form').onsubmit({preventDefault(){}});assert.equal(requests.length,before,'Stored active state must be refreshed');assert.match(ids.get('message').textContent,/Refresh stored active state/);ids.get('active-confirm').checked=false;
  await ids.get('active-refresh').onclick();assert.equal(ids.get('active-confirm').checked,false);assert.equal(ids.get('active-execute').disabled,true);
  ids.get('active-confirm').checked=true;ids.get('active-confirm').onchange();assert.equal(ids.get('active-execute').disabled,false);
  explicitSubmit=true;await ids.get('active-form').onsubmit({preventDefault(){}});explicitSubmit=false;
  const submitted=requests.find(r=>r.method==='POST');const body=JSON.parse(submitted.body);assert.equal(body.finding_id,6);assert.equal(body.module,'validation');assert.equal(body.scheme,'https');assert.equal(body.path,'/login');assert.deepEqual(body.query,{});assert.deepEqual(body.headers,{});assert.equal(body.confirmed,true);assert.equal(submitted.headers['X-CSRF-Token'],'test-only');assert.equal(ids.get('active-confirm').checked,false);
  assert.match(html,/Reports/);assert.match(html,/Provider not configured/);assert.match(fs.readFileSync(path.join(__dirname,'../../app/static/css/main.css'),'utf8'),/prefers-reduced-motion/);
  return{passed:true,shell_navigation:true,entity_edge_inspector:true,evidence_hash_and_links:true,timeline_findings_activity:true,real_id_discovery_only:true,incremental_positions_preserved:true,reduced_motion:true,empty_states:true,stale_case_poll_discarded:true,prepare_no_requests:true,prepare_errors_visible:true,prepared_state_reset:true,fresh_confirmation_and_finding_id:true,requests:requests.length};
};
