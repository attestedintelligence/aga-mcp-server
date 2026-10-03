// Runs only in the bounded, offline disposable container defined by the workflow.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
assert(process.env.AGA_DISPOSABLE_CHECK==='1'&&process.platform==='linux'&&process.getuid()!==0,'Disposable non-root Linux context required');
const input=JSON.parse(fs.readFileSync('/app/input.json','utf8'));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(fs.readFileSync('/app/verifier.tgz')),input.npm.sha256);
assert.equal(sha(fs.readFileSync('/app/'+input.python.filename)),input.python.sha256);
const genuine=fs.readFileSync('/app/sample.json');assert.equal(sha(genuine),input.sample.sha256);
const original=JSON.parse(genuine);assert(original.receipts.length>=2&&/^[a-f0-9]{64}$/.test(original.public_key));
const js='/app/npm/node_modules/@attested-intelligence/aga-verify/dist/aga-verify.mjs';
assert.equal(JSON.parse(fs.readFileSync('/app/npm/node_modules/@attested-intelligence/aga-verify/package.json','utf8')).version,input.npm.version);
const py='/app/venv/bin/aga';
function invoke(command,args){const run=spawnSync(command,args,{timeout:12_000,maxBuffer:256*1024,encoding:'utf8',env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/tmp',PYTHONDONTWRITEBYTECODE:'1'}});return{code:run.status,signal:run.signal,error:run.error?.message,output:(run.stdout||'')+(run.stderr||'')};}
const pyVersion=invoke(py,['--version']);assert.equal(pyVersion.code,0);assert.equal(pyVersion.output.trim(),'aga '+input.python.version);
const cases=[];
function save(name,body,expected=1,options=[]){const file='/tmp/'+name+'.json';fs.writeFileSync(file,typeof body==='string'?body:JSON.stringify(body));cases.push({name,file,expected,options});}
save('genuine',original,0);
save('expected-key',original,0,['--pubkey',original.public_key]);
const changed=structuredClone(original), denied=changed.receipts.find(receipt=>receipt.decision==='DENIED');assert(denied,'No denied receipt for a real mutation');denied.decision='PERMITTED';save('changed-decision',changed);
const truncated=structuredClone(original);truncated.receipts.pop();save('truncated-chain',truncated);
const signature=structuredClone(original);assert(typeof signature.receipts[0].signature==='string');signature.receipts[0].signature='0'.repeat(signature.receipts[0].signature.length);save('corrupted-signature',signature);
const reordered=structuredClone(original);[reordered.receipts[0],reordered.receipts[1]]=[reordered.receipts[1],reordered.receipts[0]];assert.notDeepEqual(reordered,original);save('reordered-receipts',reordered);
save('deep-json','{"a":'.repeat(100_000)+'1'+'}'.repeat(100_000));
const wrongKey=original.public_key==='0'.repeat(64)?'1'.repeat(64):'0'.repeat(64);
save('wrong-key',original,1,['--pubkey',wrongKey]);
save('malformed-key',original,2,['--pubkey','invalid']);
save('missing-key',original,2,['--pubkey']);
save('unknown-option',original,2,['--not-an-option']);
const results=[];
function acceptable(run,expected,engine){
 if(run.error||run.signal||run.code!==expected||/Traceback|\n\s+at\s/.test(run.output))return false;
 if(expected===2)return !/OVERALL:\s*VERIFIED|Verification:\s*PASSED/.test(run.output);
 return (engine==='npm'?new RegExp(`OVERALL: ${expected===0?'VERIFIED':'FAILED'}`):new RegExp(`Verification: ${expected===0?'PASSED':'FAILED'}`)).test(run.output);
}
// Controls prove crashes, timeouts, missing verdicts and an always-PASS result cannot masquerade as rejection.
const controls=[
 {code:0,output:'OVERALL: VERIFIED'}, {code:null,error:'timeout',output:''},
 {code:1,output:'Error\n    at malicious.js:1'}, {code:1,output:'no verdict'},
];
assert(controls.every(control=>!acceptable(control,1,'npm')));
assert(acceptable({code:1,output:'OVERALL: FAILED'},1,'npm'));
for(const item of cases)for(const engine of ['npm','python']){
 const run=engine==='npm'?invoke(process.execPath,[js,item.file,...item.options]):invoke(py,['verify',item.file,...item.options]);
 results.push({case:item.name,engine,expectedExit:item.expected,...run,passed:acceptable(run,item.expected,engine)});
}
const dependencies=invoke('/app/venv/bin/python',['-m','pip','freeze']);assert.equal(dependencies.code,0);
const report={schema:1,checkedAt:new Date().toISOString(),commit:process.env.QUALIFIED_COMMIT,input,runtime:{node:process.version,pythonDependencies:dependencies.output.trim().split('\n')},scope:'Published npm and Python verifier CLI sample controls in a disposable offline non-root container. No production signing or enforcement claim.',controls:5,results,passed:results.every(row=>row.passed)};
fs.writeFileSync('/evidence/report.json',JSON.stringify(report,null,2)+'\n');
console.log('AGA_PUBLISHED_VERIFIER_REPORT='+Buffer.from(JSON.stringify(report)).toString('base64'));

// Separate byte-preserving characterization. Never parse/re-serialize these inputs
// before invoking a published CLI. This records parser differences rather than
// extending the historical parsed-object conformance claim to raw file bytes.
const source = genuine.toString('utf8');
assert.match(source, /"leaf_index"\s*:\s*0\b/);
assert.match(source, /"decision"\s*:\s*"(?:PERMITTED|DENIED)"/);
const firstDecision = source.match(/"decision"\s*:\s*"(PERMITTED|DENIED)"/)[1];
const otherDecision = firstDecision === 'PERMITTED' ? 'DENIED' : 'PERMITTED';
const inject = prefix => Buffer.concat([Buffer.from(prefix), genuine.subarray(genuine.indexOf(123) + 1)]);
const rawCases = [
  { name: 'original-file-bytes', bytes: genuine, expectedExit: 0 },
  { name: 'duplicate-decision-original-last', bytes: Buffer.from(source.replace(/"decision"\s*:\s*"(?:PERMITTED|DENIED)"/, match => `"decision":"${otherDecision}",${match}`)), expectedExit: 0 },
  { name: 'duplicate-decision-changed-last', bytes: Buffer.from(source.replace(/"decision"\s*:\s*"(?:PERMITTED|DENIED)"/, match => `${match},"decision":"${otherDecision}"`)), expectedExit: 1 },
  { name: 'leaf-index-decimal-spelling', bytes: Buffer.from(source.replace(/("leaf_index"\s*:\s*)0\b/, '$10.0')) },
  { name: 'leaf-index-exponent-spelling', bytes: Buffer.from(source.replace(/("leaf_index"\s*:\s*)0\b/, '$10e0')) },
  { name: 'unsigned-unicode-field', bytes: inject('{"compatibility_note":"synthetic \\uD83D\\uDD0E",'), expectedExit: 0 },
  { name: 'invalid-utf8-unsigned-field', bytes: Buffer.concat([Buffer.from('{"compatibility_note":"'), Buffer.from([0xff]), Buffer.from('",'), genuine.subarray(genuine.indexOf(123) + 1)]) },
  { name: 'utf8-byte-order-mark', bytes: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), genuine]) },
  { name: 'changed-signed-decision-bytes', bytes: Buffer.from(source.replace(/"decision"\s*:\s*"(?:PERMITTED|DENIED)"/, `"decision":"${otherDecision}"`)), expectedExit: 1 },
];
const rawResults = [];
fs.mkdirSync('/evidence/raw-inputs', { recursive: true });
for (const item of rawCases) {
  const file = `/tmp/raw-${item.name}.json`;
  fs.writeFileSync(file, item.bytes);
  fs.writeFileSync(`/evidence/raw-inputs/${item.name}.json`, item.bytes);
  assert.equal(sha(fs.readFileSync(file)), sha(item.bytes));
  for (const engine of ['npm', 'python']) {
    const args = [file, '--pubkey', original.public_key];
    const run = engine === 'npm' ? invoke(process.execPath, [js, ...args]) : invoke(py, ['verify', ...args]);
    const completedWithoutCrash = !run.error && !run.signal && [0, 1, 2].includes(run.code) && !!run.output.trim() && !/Traceback|\n\s+at\s/.test(run.output);
    const expectedMet = item.expectedExit === undefined ? null : acceptable(run, item.expectedExit, engine);
    rawResults.push({ case: item.name, engine, bytes: item.bytes.length, sha256: sha(item.bytes), expectedExit: item.expectedExit ?? null, completedWithoutCrash, expectedMet, ...run });
  }
}
const rawReport = { schema: 1, checkedAt: new Date().toISOString(), commit: process.env.QUALIFIED_COMMIT, input,
  scope: 'Exact file bytes against the downloaded npm and Python CLIs, with an expected key. Numeric spelling, invalid UTF-8 and BOM rows characterize compatibility; acceptance agreement is not presumed. No Go or browser parity claim.',
  results: rawResults, passed: rawResults.every(row => row.completedWithoutCrash && row.expectedMet !== false) };
fs.writeFileSync('/evidence/raw-byte-report.json', JSON.stringify(rawReport, null, 2) + '\n');
console.log('AGA_RAW_BYTE_REPORT=' + Buffer.from(JSON.stringify(rawReport)).toString('base64'));
if (!rawReport.passed) { console.error('Raw-byte characterization found a crash or failed known control'); process.exitCode = 1; }
if(!report.passed){console.error('Published verifier qualification failed');process.exitCode=1;}
