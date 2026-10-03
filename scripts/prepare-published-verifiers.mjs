import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

const destination=process.argv[2];assert(destination && path.isAbsolute(destination));
await fs.mkdir(destination,{recursive:true});
async function download(url,limit=8*1024*1024){
 const target=new URL(url);assert(target.protocol==='https:'&&['registry.npmjs.org','pypi.org','files.pythonhosted.org'].includes(target.hostname));
 const res=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(30_000)});assert.equal(res.status,200);
 const parts=[];let size=0;for await(const part of res.body){size+=part.length;assert(size<=limit,'Download exceeds limit');parts.push(part);}return Buffer.concat(parts,size);
}
const npm=JSON.parse(await download('https://registry.npmjs.org/@attested-intelligence%2Faga-verify/latest'));
const python=JSON.parse(await download('https://pypi.org/pypi/aga-governance/json'));
assert.equal(npm.name,'@attested-intelligence/aga-verify');assert.equal(python.info.name,'aga-governance');
assert(/^\d+\.\d+\.\d+$/.test(npm.version)&&/^\d+\.\d+\.\d+$/.test(python.info.version));
assert(/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(npm.dist.integrity));
const wheel=python.urls.find(file=>file.packagetype==='bdist_wheel'&&file.filename.endsWith('-py3-none-any.whl'));
assert(wheel&&!wheel.yanked&&/^[\w.-]+\.whl$/.test(wheel.filename)&&/^[a-f0-9]{64}$/.test(wheel.digests.sha256));
const tar=await download(npm.dist.tarball), whl=await download(wheel.url);
assert.equal('sha512-'+createHash('sha512').update(tar).digest('base64'),npm.dist.integrity);
assert.equal(createHash('sha256').update(whl).digest('hex'),wheel.digests.sha256);
const sample=await fs.readFile('independent-verifier/example-bundle.json');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
await fs.writeFile(path.join(destination,'verifier.tgz'),tar);
await fs.writeFile(path.join(destination,wheel.filename),whl);
await fs.writeFile(path.join(destination,'sample.json'),sample);
await fs.copyFile('scripts/check-published-verifiers.mjs',path.join(destination,'check.mjs'));
await fs.copyFile('scripts/published-verifiers.Dockerfile',path.join(destination,'Dockerfile'));
await fs.writeFile(path.join(destination,'input.json'),JSON.stringify({npm:{name:npm.name,version:npm.version,sha256:sha(tar),integrity:npm.dist.integrity},python:{name:python.info.name,version:python.info.version,filename:wheel.filename,sha256:sha(whl)},sample:{sha256:sha(sample)}},null,2));
console.log(`Prepared registry-verified archives: npm ${npm.version}, Python ${python.info.version}. No verifier executed during preparation.`);
