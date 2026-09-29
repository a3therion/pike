// Execute the shipped renderer against hostile captured values; no browser needed.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(path.join(__dirname, '../crates/pike/src/inspector/ui.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes = new Map();
const get = id => {
  if (!nodes.has(id)) nodes.set(id, {value:'',textContent:'',innerHTML:'',style:{},classList:{add(){},remove(){}}});
  return nodes.get(id);
};
const context = vm.createContext({document:{getElementById:get,addEventListener(){}},Date,console,AbortSignal});
vm.runInContext(script,context);
const hostile = '<img src=x onerror=alert(1)>"\'&';
const request = {id:'018fbeee-0000-0000-0000-000000000001',method:'GET',path:'/'+hostile,body:hostile,response_body:hostile,headers:[{name:'x-fixture',value:hostile}],response_headers:[{name:'x-reply',value:hostile}],timestamp:new Date().toISOString(),response_status:200,duration_ms:12};
context.fixture = request;
vm.runInContext('allRequests=[fixture];renderTable();showDetail(fixture.id)',context);
for (const id of ['tbody','detail-panel']) {
  const markup=get(id).innerHTML;
  assert(!markup.includes('<img'), `${id} inserts untrusted markup`);
  assert(markup.includes('&lt;img'), `${id} should display escaped text`);
  assert(markup.includes('&quot;') && markup.includes('&#39;') && markup.includes('&amp;'));
}
vm.runInContext(`for(let i=0;i<1100;i++) receiveRequest({...fixture,id:'request-'+i});`,context);
assert.equal(vm.runInContext('allRequests.length',context),1000);
assert.equal(vm.runInContext('allRequests[0].id',context),'request-100');
context.fetch=async()=>({ok:true,json:async()=>[{origin:'http://example.test',checked:true,healthy:true,stale:true}]});
(async()=>{
  await vm.runInContext('fetchOrigins()',context);
  assert(get('origin-status').textContent.includes('check expired'));
  console.log('PASS inspector: captured text is escaped; expired health is explicit; live view retains at most 1000 rows (DOM stub, no browser visual QA)');
})().catch(error=>{console.error(error);process.exitCode=1;});
