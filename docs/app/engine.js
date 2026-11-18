// Shared CIAM risk engine + event bus (runs fully in the browser for the demo)
const BUS = new BroadcastChannel('ciam-lab');
const USERS = {
  'alex@demo.com':  {pw:'Fairway#2026', name:'Alex', points:1250, email:'alex@demo.com'},
  'sam@demo.com':   {pw:'Summer2024!',  name:'Sam',  points:480,  email:'sam@demo.com'},   // breached password
};
const BREACHED = new Set(['Summer2024!','Password1','Welcome123','Qwerty123']);
const W = {new_device:35, risky_network:30, breached_password:30, velocity:35, failed_attempts:20};
const LOCK_AFTER = 10;   // PCI DSS 8.3.4
const ld = (k,d)=>{try{return JSON.parse(localStorage.getItem(k))??d}catch{return d}};
const sv = (k,v)=>{try{localStorage.setItem(k,JSON.stringify(v))}catch{}};
function deviceId(){let d=ld('lab.device');if(!d){d='dev-'+Math.random().toString(16).slice(2,10);sv('lab.device',d)}return d}
function emit(e){e.ts=new Date().toLocaleTimeString();const log=ld('lab.log',[]);log.unshift(e);sv('lab.log',log.slice(0,300));BUS.postMessage(e)}
function score(sig){let s=0,r=[];for(const k in sig)if(sig[k]){s+=W[k];r.push(k)}s=Math.min(s,100);
  return {score:s, decision:s>=70?'BLOCK':s>=35?'CHALLENGE':'ALLOW', reasons:r}}
function fails(u){return ld('lab.fails',{})[u]||0}
function setFails(u,n){const f=ld('lab.fails',{});f[u]=n;sv('lab.fails',f)}
function isLocked(u){return fails(u)>=LOCK_AFTER}
function trusted(u){return (ld('lab.trusted',{})[u]||[]).includes(deviceId())}
function trust(u){const t=ld('lab.trusted',{});(t[u]=t[u]||[]).push(deviceId());sv('lab.trusted',t)}
function login(u,pw,opts={}){
  u=(u||'').toLowerCase().trim(); const dev=opts.device||deviceId();
  if(isLocked(u)){emit({kind:'login',user:u,device:dev,decision:'BLOCK',reasons:['account_locked'],score:100});return {decision:'LOCKED'}}
  const acct=USERS[u];
  if(!acct||acct.pw!==pw){const n=fails(u)+1;setFails(u,n);
    emit({kind:'login',user:u||'(blank)',device:dev,decision:'FAIL',reasons:[acct?'bad_password':'unknown_user',`attempt ${n}/${LOCK_AFTER}`],score:0});
    if(n===LOCK_AFTER)emit({kind:'alert',text:`Account ${u} locked after ${LOCK_AFTER} failed attempts (PCI DSS 8.3.4)`});
    return {decision:'FAIL',remaining:Math.max(LOCK_AFTER-n,0)}}
  const r=score({new_device:opts.newDevice??!trusted(u), risky_network:!!opts.risky, breached_password:BREACHED.has(pw), failed_attempts:fails(u)>=3});
  emit({kind:'login',user:u,device:dev,...r}); return r}
function makeCode(){const c=String(Math.floor(100000+Math.random()*900000));sv('lab.mfa',c);return c}
function checkCode(c){return c===ld('lab.mfa','')}
function resetLab(){['lab.fails','lab.trusted','lab.log','lab.session','lab.mfa'].forEach(k=>localStorage.removeItem(k));BUS.postMessage({kind:'reset'})}
