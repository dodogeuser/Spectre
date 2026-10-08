/* Offline application UI checks with real vendored Cytoscape, no browser/network. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const cytoscape = require('../../app/static/vendor/cytoscape.min.js');
const {storedGraphSelection} = require('../../app/static/js/investigation.js');

module.exports = async function run() {
  const data = {entities: Array.from({length:2000}, (_,i)=>({id:i+1,type:i%2?'ip':'domain',value:`node${i}`,roles:[],attributes:{}})), relationships: Array.from({length:1999},(_,i)=>({from:i+1,to:i+2,type:'resolves_to',confidence:.95,classification:'observed',sources:['dns'],evidence_ids:[1],first_seen:'2026-10-06T00:00:00',last_seen:'2026-10-06T00:00:00',rule:'DNS answer'})), evidence:[{id:1,run_id:1,source_type:'dns',source_ref:'fixture://stored',captured_at:'2026-10-06T00:00:00',sha256:'a'.repeat(64),collector:'dns',version:'1.0.0'}]};
  assert.equal(storedGraphSelection(data).nodes.length,2000);
  assert.equal(storedGraphSelection(data,{source:'ct'}).edges.length,0);
  assert.equal(storedGraphSelection(data,{confidence:1}).edges.length,0);
  assert.equal(storedGraphSelection(data,{type:'ip'}).nodes.length,1000);
  class Element {
    constructor(tag='div') {this.tag=tag;this.children=[];this.value='';this.textContent='';this.hidden=false;}
    append(...nodes){this.children.push(...nodes);}
    replaceChildren(...nodes){this.children=nodes;}
    set innerHTML(value){throw Error('Untrusted HTML must never be injected');}
  }
  const ids=new Map(); const document={getElementById(id){if(!ids.has(id))ids.set(id,new Element());return ids.get(id);},createElement(tag){return new Element(tag);}};
  for(const match of fs.readFileSync(path.join(__dirname,'../../app/static/index.html'),'utf8').matchAll(/id="([^"]+)"/g))document.getElementById(match[1]);
  const requests=[];let lastCy;
  const context={document,window:{},selectedCase:{id:7},console,module:undefined,Set,Number,JSON,setTimeout,clearTimeout,
    cytoscape(options){lastCy=cytoscape({...options,elements:JSON.parse(JSON.stringify(options.elements)),container:undefined,headless:true,styleEnabled:false});return lastCy;},
    showError(error){throw error;},async api(url,method='GET'){
      requests.push({url,method});assert.equal(method,'GET');assert.match(url,/^\/api\/cases\/7\//);
      if(url.endsWith('/investigation'))return data;
      if(url.includes('/timeline'))return {events:[{timestamp:'2026-10-06T00:00:00',type:'evidence.captured',source:'dns',evidence_ids:[1],run_ids:[1],entity_ids:[]}],bounded_total:1,has_more:false,truncated:false};
      if(url.includes('/detail'))return {entity:data.entities[0],relationships:[data.relationships[0]],evidence:data.evidence,first_seen:'2026-10-06T00:00:00',last_seen:'2026-10-06T00:00:00',has_more:false};
      if(url.includes('/evidence/'))return {id:1,run_id:1,captured_at:'2026-10-06T00:00:00',source_type:'dns',source_ref:'fixture://stored',sha256:'a'.repeat(64),parsed_json:{title:'<script>never execute</script>'},raw_json:{html:'<img onerror=alert(1)>'}};
      throw Error('Unexpected request');
    }};
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../../app/static/js/investigation.js'),'utf8'),context);
  await ids.get('graph-load').onclick();
  assert.equal(lastCy.nodes().length,200);assert.equal(lastCy.edges().length,199);
  assert.equal(new Set(lastCy.edges().map(e=>e.id())).size,199);
  ids.get('graph-more').onclick();assert.equal(lastCy.nodes().length,400);
  ids.get('graph-source').value='ct';ids.get('graph-apply').onclick();assert.equal(lastCy.nodes().length,0);
  ids.get('graph-reset').onclick();ids.get('graph-search').value='node1500';ids.get('graph-focus').onclick();
  await new Promise(resolve=>setImmediate(resolve));assert.equal(lastCy.nodes().length,1);
  ids.get('graph-expand').onclick();assert.equal(lastCy.nodes().length,3);assert.equal(lastCy.edges().length,2);
  lastCy.edges()[0].emit('tap');assert.ok(ids.get('graph-detail').children.some(n=>n.textContent.includes('resolves_to')));
  const evidenceButton=ids.get('graph-detail').children.find(n=>n.tag==='button');await evidenceButton.onclick();
  assert.ok(ids.get('graph-detail').children.some(n=>n.tag==='pre'&&n.textContent.includes('<script>never execute</script>')));
  assert.ok(requests.every(r=>r.method==='GET'));
  assert.equal(cytoscape.version,'3.33.1');context.window.resetInvestigation();assert.equal(ids.get('graph-controls').hidden,true);
  return {passed:true,library:cytoscape.version,synthetic_nodes:2000,initial_visible_nodes:200,expansion_edges:2,requests:requests.length,no_collector_requests:true,inert_evidence:true};
};
