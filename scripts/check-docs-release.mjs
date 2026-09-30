// Gate only the documentation release. No product code is executed here.
import fs from 'node:fs';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';

const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const allowed=new Set(['package/README.md','package/CHANGELOG.md','package/package.json','package/DEPLOYMENT.md','package/SECURITY.md','package/THREAT_BOUNDARY.md']);
function unpack(bytes){
  const raw=zlib.gunzipSync(bytes,{maxOutputLength:16*1024*1024}),files=new Map();
  for(let offset=0;offset+512<=raw.length;){
    const h=raw.subarray(offset,offset+512);if(h.every(b=>b===0))break;
    const string=(a,n)=>h.subarray(a,a+n).toString().split('\0')[0];
    const name=string(0,100),prefix=string(345,155),size=parseInt(string(124,12).trim(),8),mode=parseInt(string(100,8).trim(),8);
    assert(!prefix&&name.startsWith('package/')&&!name.split('/').some(s=>s==='..')&&!files.has(name),'Unexpected tar path');
    assert(h[156]===48||h[156]===0,'Only regular files are permitted');
    assert(Number.isSafeInteger(size)&&size>=0&&offset+512+size<=raw.length,'Invalid tar size');
    const expected=parseInt(string(148,8).trim(),8);let sum=0;for(let i=0;i<512;i++)sum+=i>=148&&i<156?32:h[i];assert(sum===expected,'Tar checksum mismatch');
    files.set(name,{bytes:raw.subarray(offset+512,offset+512+size),mode});offset+=512+Math.ceil(size/512)*512;
  }
  assert(files.size===207,'Expected the complete 207-member package');return files;
}
function compare(before,after){
  assert.deepEqual([...after.keys()].sort(),[...before.keys()].sort(),'Member set changed');
  let unchanged=0;
  for(const [name,old] of before){const current=after.get(name);assert.equal(current.mode,old.mode,'File mode changed: '+name);if(old.bytes.equals(current.bytes))unchanged++;else assert(allowed.has(name),'Runtime or supporting file changed: '+name);}
  const a=JSON.parse(before.get('package/package.json').bytes),b=JSON.parse(after.get('package/package.json').bytes);
  assert.equal(b.version,'3.6.4');delete a.version;delete b.version;delete a.description;delete b.description;assert.deepEqual(b,a,'Package behavior or dependency changed');
  return unchanged;
}
if(process.argv.includes('--self-test')){
  const source=process.argv[process.argv.indexOf('--self-test')+1];assert(source,'A reviewed baseline tarball path is required');
  const baseline=unpack(fs.readFileSync(source));
  const candidate=()=>{const m=new Map([...baseline].map(([k,v])=>[k,{...v,bytes:Buffer.from(v.bytes)}]));const p=JSON.parse(m.get('package/package.json').bytes);p.version='3.6.4';m.get('package/package.json').bytes=Buffer.from(JSON.stringify(p));return m;};
  assert.equal(compare(baseline,candidate()),206);
  let m=candidate();m.get('package/dist/index.js').bytes=Buffer.from('changed');assert.throws(()=>compare(baseline,m));
  m=candidate();m.delete('package/LICENSE');assert.throws(()=>compare(baseline,m));
  m=candidate();m.set('package/extra',{bytes:Buffer.from('extra'),mode:420});assert.throws(()=>compare(baseline,m));
  m=candidate();m.get('package/dist/index.js').mode=0;assert.throws(()=>compare(baseline,m));
  m=candidate();const p=JSON.parse(m.get('package/package.json').bytes);p.scripts.test='changed';m.get('package/package.json').bytes=Buffer.from(JSON.stringify(p));assert.throws(()=>compare(baseline,m));
  console.log('Documentation gate: six synthetic controls passed; no package code executed.');
}else{
  const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));
  if(pkg.version!=='3.6.4'){console.log('Documentation identity gate applies to 3.6.4 only.');process.exit(0);}
  const response=await fetch('https://registry.npmjs.org/@attested-intelligence/aga-mcp-server/-/aga-mcp-server-3.6.3.tgz',{signal:AbortSignal.timeout(30000)});assert(response.ok);
  const bytes=Buffer.from(await response.arrayBuffer());assert.equal(digest(bytes),'c9f81cd48d623557034613ff9cadb6a1580045c43f89f6f6ac954896ad5771e3','Baseline archive identity changed');
  const packed=JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json'],{encoding:'utf8',maxBuffer:1024*1024}));assert.equal(packed.length,1);
  const filename=packed[0].filename;assert.equal(filename,'attested-intelligence-aga-mcp-server-3.6.4.tgz');
  const unchanged=compare(unpack(bytes),unpack(fs.readFileSync(filename)));
  console.log(JSON.stringify({passed:true,members:207,unchanged,allowedChanges:[...allowed],scope:'Exact runtime bytes and package behavior unchanged from reviewed 3.6.3.'}));
}
