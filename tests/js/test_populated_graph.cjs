/* Portable synthetic stored graph; no private snapshots or collection. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const cytoscape=require('../../app/static/vendor/cytoscape.min.js');
module.exports=async function(caseId=7){
  const stamp='2026-01-01T00:00:00';
  const entities=Array.from({length:21},(_,i)=>({id:i+1,type:i===0?'domain':i<16?'ip':'certificate',value:i===0?'example.com':i<16?`192.0.2.${i}`:String(i).padStart(64,'0'),roles:[],attributes:{},evidence_ids:[1],sources:['dns']}));
  const relationships=Array.from({length:24},(_,i)=>({from:i<20?1:2,to:i<20?i+2:i-17,type:i%20<15?'resolves_to':'certificate_for',classification:i<20?'observed':'derived',rule:'Synthetic stored relationship',confidence:.95,evidence_ids:[1],support_ids:[i+1],first_seen:stamp,last_seen:stamp,sources:['dns']}));
  // Distinct stored rules for additional relationships preserve unique identity.
  relationships.forEach((r,i)=>r.rule+=` ${i}`);
  const fixture={targets:[{id:1,case_id:caseId,type:'domain',value:'example.com',normalized_value:'example.com',scope_status:'passive_allowed',archived:false}],graph:{case_id:caseId,entities,relationships,evidence:[{id:1,run_id:1,target_id:1,source_type:'synthetic',source_ref:'mock://fixture',captured_at:stamp,sha256:'a'.repeat(64),collector:'mock',version:'1.0.0'}]},timeline:{events:[],bounded_total:0,has_more:false,truncated:false}};
  class Element{constructor(tag='div'){this.tag=tag;this.children=[];this.value='';this.hidden=false;this.textContent='';}append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}set innerHTML(v){throw Error('No untrusted HTML');}}
  const ids=new Map(),document={getElementById(id){if(!ids.has(id))ids.set(id,new Element());return ids.get(id);},createElement(tag){return new Element(tag);}};
  for(const m of fs.readFileSync(path.join(__dirname,'../../app/static/index.html'),'utf8').matchAll(/id="([^"]+)"/g))document.getElementById(m[1]);
  let cy;const requests=[],context={document,window:{},selectedCase:{id:caseId},console,Set,Map,Date,Number,JSON,setTimeout,clearTimeout,
    showError(e){throw e;},cytoscape(options){cy=cytoscape({...options,container:undefined,headless:true,styleEnabled:false});return cy;},
    async api(url){requests.push(url);if(url.endsWith('/investigation'))return fixture.graph;if(url.includes('/timeline?'))return fixture.timeline;throw Error('Unexpected request '+url);}};
  vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../../app/static/js/investigation.js'),'utf8'),context);
  context.window.updateInvestigationTargets(fixture.targets);await ids.get('graph-load').onclick();
  const defaultNodes=cy.nodes().length,defaultEdges=cy.edges().length;
  assert.ok(cy.nodes().length<fixture.graph.entities.length,'Default certificate collapse reduces visual clutter without changing stored counts');
  ids.get('graph-certificates').value='expanded';ids.get('graph-certificates').onchange();
  assert.equal(cy.nodes().length,fixture.graph.entities.length);assert.equal(cy.edges().length,fixture.graph.relationships.length);assert.equal(cy.nodes().filter(n=>n.data('root')===1).length,fixture.targets.length);assert.equal(cy.nodes().filter(n=>n.id().startsWith('t')).length,0);
  assert.equal(cy.elements('.new-discovery').length,0,'Existing stored records do not animate on load');
  for(const layout of ['cose','breadthfirst','concentric','grid']){ids.get('graph-layout').value=layout;ids.get('graph-relayout').onclick();assert.ok(cy.nodes().every(n=>Number.isFinite(n.position('x'))&&Number.isFinite(n.position('y'))));}
  assert.ok(cy.edges().every(e=>e.data('stored').evidence_ids.length&&e.data('stored').support_ids.length));
  assert.equal(new Set(cy.edges().map(e=>e.id())).size,fixture.graph.relationships.length);
  context.window.resetInvestigation();assert.ok(requests.every(url=>!url.includes('/collectors/')));
  return{passed:true,synthetic_case:caseId,defaultNodes,defaultEdges,entities:fixture.graph.entities.length,relationships:fixture.graph.relationships.length,merged_target_roots:fixture.targets.length,layouts:['cose','breadthfirst','concentric','grid'],visual_geometry_verified:false};
};
