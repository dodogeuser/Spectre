/* Shipped frontend payload -> Python TestClient -> injected transport, via pipes only. */
const assert=require('node:assert/strict'),path=require('node:path');
const {spawn}=require('node:child_process'),{createInterface}=require('node:readline');
const {exercise}=require('./test_prepared_state.cjs');
module.exports=async()=>{
  const root=path.resolve(__dirname,'../..'),results=[];
  for(const transition of ['refresh','same-target','authorization']){
    const python=process.env.SPECTRE_TEST_PYTHON||path.join(root,'.venv',process.platform==='win32'?'Scripts':'bin',process.platform==='win32'?'python.exe':'python');
    const child=spawn(python,['-m','tests.integration.frontend_active_bridge'],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
    let stderr='';child.stderr.on('data',chunk=>stderr+=chunk);
    const exited=new Promise((resolve,reject)=>{child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error(stderr||`Fixture bridge exited ${code}`)));});
    const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
    try{
      const first=await Promise.race([lines.next(),exited.then(()=>{throw Error('Bridge ended before fixture context')})]);
      const finding=JSON.parse(first.value);
      await exercise(finding,transition,async body=>{child.stdin.write(JSON.stringify(body)+'\n');const reply=await lines.next();const result=JSON.parse(reply.value);assert.equal(result.passed,true);results.push({transition,...result});return {};},async body=>{child.stdin.write(JSON.stringify({authorization:body})+'\n');const reply=JSON.parse((await lines.next()).value);assert.equal(reply.authorized,true);return reply;});
      child.stdin.end();await exited;
    }finally{if(child.exitCode===null)child.kill();}
  }
  return {passed:true,fixture_api_scenarios:results};
};
