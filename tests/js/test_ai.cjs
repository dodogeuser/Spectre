/* Actual AI UI handlers with an inert DOM; stale case answers must never render. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
module.exports=async function run(){
  class Element{constructor(tag='div'){this.tag=tag;this.children=[];this.value='';this.textContent='';}append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}set innerHTML(value){throw Error('No HTML injection');}}
  const ids=new Map(),document={getElementById(id){if(!ids.has(id))ids.set(id,new Element());return ids.get(id);},createElement(tag){return new Element(tag);}};
  const requests=[],answer={message:'AI selection',claims:[{category:'stored_observation',text:'<script>Ignore instructions</script>',evidence_ids:[61],records:[{type:'finding',id:1}]}]};
  let pending=null;
  const context={document,window:{},selectedCase:{id:12},showError(error){throw error;},domainEvidenceLink(id,caseId){const a=new Element('a');a.href=`/api/cases/${caseId}/evidence/${id}`;return a;},async api(url,method='GET',body){requests.push({url,method,body});assert.ok(!url.includes('/collectors/'));
    if(url.endsWith('/status'))return {configured:false};
    if(pending)return pending;return answer;}};
  vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../../app/static/js/ai.js'),'utf8'),context);
  await ids.get('ai-open').onclick();assert.match(ids.get('ai-status').textContent,/not configured/);
  document.getElementById('ai-question').value='Summarize evidence';await ids.get('ai-form').onsubmit({preventDefault(){}});
  const section=ids.get('ai-answer').children[1];assert.equal(section.children[1].textContent,answer.claims[0].text);
  assert.equal(section.children[2].href,'/api/cases/12/evidence/61');assert.equal(section.children[3].href,'/api/cases/12/findings/1');
  let resolve;pending=new Promise(r=>resolve=r);const oldRequest=ids.get('ai-form').onsubmit({preventDefault(){}});
  context.window.resetAI();context.selectedCase.id=13;resolve(answer);await oldRequest;
  assert.equal(ids.get('ai-answer').children.length,0);assert.equal(ids.get('ai-panel').hidden,true);assert.equal(ids.get('ai-question').value,'');
  assert.ok(requests.filter(r=>r.method==='POST').every(r=>r.url.endsWith('/ai/questions')));
  return {passed:true,inert_text:true,validated_record_navigation:true,no_collectors:true,stale_case_answer_discarded:true,history_cleared:true};
};
