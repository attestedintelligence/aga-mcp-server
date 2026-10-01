/** Bounded stdio transport. Child processes still share the host account; this is not privilege isolation. */
import { spawn, type ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { JsonLineFramer } from './json-lines.js';
import { parseUnambiguousJson } from './strict-json.js';

export interface StdioBridgeOptions { command: string; args?: string[]; env?: Record<string,string>; cwd?: string; }
const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;
const MAX_PENDING = 128;
type Pending = { resolve: (response: Record<string,unknown>) => void; reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>; cleanup: () => void; originalId: string | number };

/** Explicit environment, with no implicit signing secrets or shell interpolation. */
export function downstreamEnvironment(extra: Record<string,string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of ['PATH','Path','SystemRoot','WINDIR','PATHEXT','TEMP','TMP','LANG','LC_ALL']) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  for (const [name,value] of Object.entries(extra)) {
    if (/^AGA_GATEWAY_KEY(?:_FILE)?$/i.test(name)) throw new Error('Gateway signing credentials cannot be forwarded to a downstream child');
    env[name] = value;
  }
  return env;
}
export class StdioBridge extends EventEmitter {
  private child: ChildProcess | null = null;
  private framer = new JsonLineFramer(MAX_MESSAGE_BYTES);
  private pendingRequests = new Map<string,Pending>();
  constructor(private options: StdioBridgeOptions) { super(); }
  async start(): Promise<void> {
    if (this.child) throw new Error('Bridge already started');
    const {command,args=[],env,cwd} = this.options;
    const child = spawn(command,args,{stdio:['pipe','pipe','pipe'],env:downstreamEnvironment(env),cwd,shell:false});
    this.child = child; this.framer = new JsonLineFramer(MAX_MESSAGE_BYTES);
    child.stdout!.on('data',(chunk: Buffer)=>{
      try {
        for (const line of this.framer.push(chunk)) {
          const msg = parseUnambiguousJson(line);
          if (!msg || typeof msg !== 'object' || Array.isArray(msg) || (msg as Record<string,unknown>).jsonrpc !== '2.0') throw new Error('Invalid downstream frame');
          this.handleMessage(msg as Record<string,unknown>);
        }
      } catch {
        this.rejectAllPending(new Error('Downstream emitted an invalid or oversized frame'));child.kill('SIGTERM');
      }
    });
    child.stderr!.on('data',(chunk: Buffer)=>process.stderr.write(`[downstream] ${chunk.toString()}`));
    child.on('exit',(code,signal)=>{this.rejectAllPending(new Error(`Downstream process exited: code=${code} signal=${signal}`));this.emit('exit',code,signal)});
    child.on('error',error=>{this.rejectAllPending(error);this.emit('error',error)});
    await new Promise<void>((resolve,reject)=>{child.once('spawn',resolve);child.once('error',reject)});
  }
  private handleMessage(msg: Record<string,unknown>): void {
    if (Object.hasOwn(msg,'id') && (Object.hasOwn(msg,'result') || Object.hasOwn(msg,'error'))) {
      const pending = typeof msg.id === 'string' ? this.pendingRequests.get(msg.id) : undefined;
      if (!pending) return;
      this.pendingRequests.delete(msg.id as string);clearTimeout(pending.timer);pending.cleanup();
      pending.resolve({...msg,id:pending.originalId});return;
    }
    this.emit('notification',msg);
  }
  private write(message: Record<string,unknown>, callback?: (error?: Error | null)=>void): void {
    if (!this.child?.stdin?.writable || !this.running) throw new Error('Downstream process not running');
    const frame=JSON.stringify(message)+'\n';
    if (Buffer.byteLength(frame)>MAX_MESSAGE_BYTES || this.child.stdin.writableLength>MAX_MESSAGE_BYTES) throw new Error('Downstream write bound exceeded');
    this.child.stdin.write(frame,callback);
  }
  async send(message: Record<string,unknown>, timeoutMs=30000, signal?: AbortSignal): Promise<Record<string,unknown>> {
    signal?.throwIfAborted();
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs<1 || timeoutMs>30000) throw new Error('Invalid request deadline');
    if (!Object.hasOwn(message,'id')) {
      this.write(message);return {jsonrpc:'2.0',result:null,id:null};
    }
    const originalId=message.id;
    if (!(typeof originalId==='string' || (typeof originalId==='number' && Number.isSafeInteger(originalId)))) throw new Error('Invalid request ID');
    if (this.pendingRequests.size>=MAX_PENDING) throw new Error('Downstream pending-request limit reached');
    const wireId='aga-'+randomUUID();
    return new Promise((resolve,reject)=>{
      const fail=(error: Error)=>{const pending=this.pendingRequests.get(wireId);if(!pending)return;this.pendingRequests.delete(wireId);clearTimeout(pending.timer);pending.cleanup();reject(error)};
      const abort=()=>fail(new Error('Request owner disconnected or canceled'));
      const timer=setTimeout(()=>fail(new Error('Downstream response deadline exceeded')),timeoutMs);
      const cleanup=()=>signal?.removeEventListener('abort',abort);
      this.pendingRequests.set(wireId,{resolve,reject,timer,cleanup,originalId});
      signal?.addEventListener('abort',abort,{once:true});
      try { this.write({...message,id:wireId},error=>{if(error)fail(error)}); }
      catch(error){fail(error instanceof Error?error:new Error('Downstream write failed'))}
    });
  }
  sendRaw(message: Record<string,unknown>): void { this.write(message); }
  async stop(): Promise<void> {
    this.rejectAllPending(new Error('Bridge stopped'));
    const child=this.child;this.child=null;
    if (!child || child.exitCode!==null || child.signalCode!==null) return;
    await new Promise<void>(resolve=>{
      const finish=()=>{clearTimeout(timer);child.removeListener('exit',finish);resolve()};
      const timer=setTimeout(()=>{child.kill('SIGKILL');finish()},3000);
      child.once('exit',finish);child.kill('SIGTERM');
    });
  }
  get running(): boolean {return this.child!==null && this.child.exitCode===null && this.child.signalCode===null}
  private rejectAllPending(error: Error): void {
    for(const pending of this.pendingRequests.values()){clearTimeout(pending.timer);pending.cleanup();pending.reject(error)}
    this.pendingRequests.clear();
  }
}
