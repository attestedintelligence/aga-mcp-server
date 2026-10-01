import {describe,it,expect} from 'vitest';
import {once} from 'node:events';
import * as net from 'node:net';
import * as http from 'node:http';
import {ProxyControlServer} from '../../src/proxy/control.js';
import {JsonLineFramer} from '../../src/proxy/json-lines.js';
import {parseUnambiguousJson} from '../../src/proxy/strict-json.js';
import {snapshotPolicy} from '../../src/proxy/policy-snapshot.js';
import {evaluate,createRateLimitState,resetRateLimits} from '../../src/proxy/evaluator.js';
import {StdioBridge,downstreamEnvironment} from '../../src/proxy/stdio-bridge.js';
import {GovernanceProxy} from '../../src/proxy/server.js';
import {SepGateway,signerFromSeed,verifySepBundle,derivePolicyReference} from '../../src/sep/index.js';
import type {ToolPolicy} from '../../src/proxy/types.js';
const makePolicy=(): ToolPolicy=>({mode:'allowlist',constraints:{read:{name:'read',allowed:true,path_prefix:'/allowed',path_keys:['path'],max_calls_per_minute:1}}});
const child=`const readline=require('node:readline');readline.createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);if(m.method==='never')return;if(!Object.hasOwn(m,'id'))return;setTimeout(()=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:m.params})+'\\n'),m.params?.delay||0)})`;
describe('byte framing',()=>{
  it('preserves UTF-8 at every byte split',()=>{
    const bytes=Buffer.from('{"text":"café 東京 🧪"}\n');
    for(let i=1;i<bytes.length;i++){const f=new JsonLineFramer(1024);expect([...f.push(bytes.subarray(0,i)),...f.push(bytes.subarray(i))]).toEqual(['{"text":"café 東京 🧪"}'])}
  });
  it('bounds each message rather than the combined TCP chunk',()=>expect(new JsonLineFramer(2).push(Buffer.from('{}\n{}\n'))).toEqual(['{}','{}']));
  it('counts bytes rather than code units',()=>expect(()=>new JsonLineFramer(3).push(Buffer.from('🧪'))).toThrow(/byte limit/));
  it('rejects malformed UTF-8',()=>expect(()=>new JsonLineFramer(1024).push(Buffer.from([0xc3,0x28,0x0a]))).toThrow());
});
describe('policy ownership and fail-closed constraints',()=>{
  it('copies and freezes caller-owned values without changing the reference',()=>{
    const source=makePolicy(),reference=derivePolicyReference(source),snapshot=snapshotPolicy(source);
    source.constraints.read.allowed=false;source.constraints.read.path_keys!.push('other');
    expect(snapshot.constraints.read.allowed).toBe(true);expect(snapshot.constraints.read.path_keys).toEqual(['path']);
    expect(Object.isFrozen(snapshot.constraints.read.path_keys)).toBe(true);expect(derivePolicyReference(snapshot)).toBe(reference);
  });
  it.each([undefined,{}, {path:7}, {path:''}])('refuses missing or invalid required paths: %s',args=>expect(evaluate(snapshotPolicy(makePolicy()),'read',args as any,createRateLimitState()).allowed).toBe(false));
  it('does not interpret prototype properties as constraints',()=>expect(evaluate({mode:'allowlist',constraints:{}},'constructor').allowed).toBe(false));
  it('applies path and pattern guards to allowed denylist entries',()=>{
    const policy=makePolicy();policy.mode='denylist';policy.constraints.read.denied_patterns=['forbidden'];
    expect(evaluate(snapshotPolicy(policy),'read',{path:'/outside'},createRateLimitState()).allowed).toBe(false);
    expect(evaluate(snapshotPolicy(policy),'read',{path:'/allowed/forbidden'},createRateLimitState()).allowed).toBe(false);
  });
  it('rate-limit resets do not affect other proxy owners',()=>{
    const p=makePolicy(),a=createRateLimitState(),b=createRateLimitState(),args={path:'/allowed/a'};
    expect(evaluate(p,'read',args,a).allowed).toBe(true);expect(evaluate(p,'read',args,b).allowed).toBe(true);
    resetRateLimits(a);expect(evaluate(p,'read',args,a).allowed).toBe(true);expect(evaluate(p,'read',args,b).allowed).toBe(false);
  });
  it('rejects policy accessors and malformed booleans before binding',()=>{
    expect(()=>snapshotPolicy({...makePolicy(),get constraints(){throw Error('getter executed')}})).toThrow();
    const p=makePolicy();p.constraints.read.allowed='yes' as any;expect(()=>snapshotPolicy(p)).toThrow();
  });
});
describe('transport ownership and cleanup',()=>{
  it('remaps duplicate client IDs into distinct downstream requests, then restores them',async()=>{
    const bridge=new StdioBridge({command:process.execPath,args:['-e',child]});bridge.on('error',()=>{});await bridge.start();
    try{
      const [a,b]=await Promise.all([bridge.send({jsonrpc:'2.0',id:1,method:'echo',params:{owner:'a',delay:20}}),bridge.send({jsonrpc:'2.0',id:1,method:'echo',params:{owner:'b'}})]);
      expect(a.id).toBe(1);expect(b.id).toBe(1);expect(a.result).toMatchObject({owner:'a'});expect(b.result).toMatchObject({owner:'b'});
    }finally{await bridge.stop()}
  });
  it('cancels an owned pending request and permits reuse of its client ID',async()=>{
    const bridge=new StdioBridge({command:process.execPath,args:['-e',child]});bridge.on('error',()=>{});await bridge.start();
    try{
      const owner=new AbortController(),pending=bridge.send({jsonrpc:'2.0',id:1,method:'never'},5000,owner.signal);
      const rejected=expect(pending).rejects.toThrow(/owner disconnected/);owner.abort();await rejected;
      expect((await bridge.send({jsonrpc:'2.0',id:1,method:'echo',params:{ok:true}})).result).toEqual({ok:true});
    }finally{await bridge.stop()}
  });
  it('does not inherit synthetic signing credentials or unrelated tokens',()=>{
    const previous=process.env.AGA_GATEWAY_KEY,token=process.env.RUNTIME_TEST_TOKEN;
    process.env.AGA_GATEWAY_KEY='synthetic-not-a-production-key';process.env.RUNTIME_TEST_TOKEN='synthetic';
    try{const env=downstreamEnvironment();expect(env.AGA_GATEWAY_KEY).toBeUndefined();expect(env.RUNTIME_TEST_TOKEN).toBeUndefined();expect(()=>downstreamEnvironment({AGA_GATEWAY_KEY:'synthetic'})).toThrow()}
    finally{if(previous===undefined)delete process.env.AGA_GATEWAY_KEY;else process.env.AGA_GATEWAY_KEY=previous;if(token===undefined)delete process.env.RUNTIME_TEST_TOKEN;else process.env.RUNTIME_TEST_TOKEN=token}
  });
  it('binds loopback, records a refused tool notification without a response, and drains an open client',async()=>{
    const proxy=new GovernanceProxy({port:0,ephemeral:true,policy:makePolicy()});await proxy.start();
    const socket=net.createConnection({host:'127.0.0.1',port:proxy.getStatus().port});await once(socket,'connect');
    let responses=0;socket.on('data',()=>responses++);
    try{socket.write(JSON.stringify({jsonrpc:'2.0',method:'tools/call',params:{name:'read',arguments:{path:'/allowed/a'}}})+'\n');
      await new Promise(r=>setTimeout(r,40));expect(responses).toBe(0);expect(proxy.getReceipts().at(-1)?.decision).toBe('DENIED');expect(proxy.getStatus().host).toBe('127.0.0.1');
      const closed=once(socket,'close');await proxy.stop();await closed;
    }finally{socket.destroy();await proxy.stop()}
  });
});
describe('unambiguous protocol JSON',()=>{
  it.each(['{"method":"echo","method":"tools/call"}','{"method":"echo","m\\u0065thod":"tools/call"}','{"params":{"name":"a","name":"b"}}'])('rejects repeated decoded names: %s',raw=>expect(()=>parseUnambiguousJson(raw)).toThrow());
  it('allows repeated names in separate objects and escaped strings',()=>expect(parseUnambiguousJson('{"a":[{"x":1},{"x":2}],"s":"a\\\"b"}')).toEqual({a:[{x:1},{x:2}],s:'a"b'}));
  it('bounds depth without an unbounded recursive parse',()=>expect(()=>parseUnambiguousJson('['.repeat(1026)+'0'+']'.repeat(1026))).toThrow());
  it.each(['{"x":01}','{"x":true,}','[1,]','{"x":"bad\ntext"}','{"x":1}junk'])('rejects invalid grammar: %s',raw=>expect(()=>parseUnambiguousJson(raw)).toThrow());
  it('refuses ambiguous requests without downstream execution',async()=>{
    const proxy=new GovernanceProxy({port:0,ephemeral:true,policy:makePolicy()});await proxy.start();
    const socket=net.createConnection({host:'127.0.0.1',port:proxy.getStatus().port});await once(socket,'connect');
    try{const reply=once(socket,'data');socket.write('{"jsonrpc":"2.0","id":1,"method":"echo","method":"tools/call"}\n');expect(JSON.parse(String((await reply)[0])).error.code).toBe(-32700);expect(proxy.getReceipts()).toHaveLength(0)}
    finally{socket.destroy();await proxy.stop()}
  });
  it('cleans up its downstream child if listener binding fails',async()=>{
    const busy=net.createServer();busy.listen(0,'127.0.0.1');await once(busy,'listening');
    const port=(busy.address() as net.AddressInfo).port;
    const proxy=new GovernanceProxy({port,ephemeral:true,upstream:{command:process.execPath,args:['-e','setInterval(()=>{},1000)']}});
    try{await expect(proxy.start()).rejects.toThrow();expect((proxy as any).bridge).toBeNull();expect((proxy as any).server).toBeNull()}
    finally{await proxy.stop();await new Promise<void>(resolve=>busy.close(()=>resolve()))}
  });
});
describe('shared runtime trust input',()=>{
  it.each(['invalid','','0'.repeat(64)])('fails a supplied invalid expected key without downgrade: %s',pin=>{
    const gw=new SepGateway({gatewayId:'synthetic',signer:signerFromSeed(new Uint8Array(32).fill(7))});
    gw.record({tool_name:'read',decision:'PERMITTED',reason:'synthetic'});const bundle=gw.exportBundle();
    expect(verifySepBundle(bundle).verdict).toBe('VERIFIED');expect(verifySepBundle(bundle,pin)).toMatchObject({verdict:'FAILED',pinned:true,issuerVerified:false});
  });
});
describe('control-channel browser boundary',()=>{
  it('refuses foreign Host and browser Origin before reading the ledger',async()=>{
    let reads=0;const read=()=>{reads++;return {synthetic:true}};
    const control=new ProxyControlServer({getStatus:read,getReceipts:read,exportBundle:read});const {port}=await control.start(0);
    const get=(headers:Record<string,string>)=>new Promise<number>((resolve,reject)=>{http.get({host:'127.0.0.1',port,path:'/status',headers},res=>{res.resume();res.on('end',()=>resolve(res.statusCode!))}).on('error',reject)});
    try{expect(await get({Host:`127.0.0.1:${port}`})).toBe(200);expect(reads).toBe(1);
      expect(await get({Host:`untrusted.example:${port}`})).toBe(403);
      expect(await get({Host:`127.0.0.1:${port}`,Origin:'https://untrusted.example'})).toBe(403);
      expect(await get({Host:`127.0.0.1:${port}`,'Sec-Fetch-Site':'cross-site'})).toBe(403);expect(reads).toBe(1);
    }finally{await control.stop()}
  });
});
