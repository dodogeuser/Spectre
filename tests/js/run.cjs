/* Optional Node test runtime only; no Node build toolchain/runtime dependency. */
const suites=['investigation','graph_presentation','populated_graph','findings','ai','reports','active','console','prepared_state','prepared_bridge'];
(async()=>{for(const suite of suites){await require(`./test_${suite}.cjs`)();console.log(`PASS ${suite}`);}})().catch(error=>{console.error(error);process.exitCode=1;});
