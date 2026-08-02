import { privateKeyToAccount } from "viem/accounts";
const acct=privateKeyToAccount(process.env.PROBE_PRIVATE_KEY);
const USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e", CHAIN=84532;
const PAYTO="0x1111111111111111111111111111111111111111";
const types={TransferWithAuthorization:[{name:"from",type:"address"},{name:"to",type:"address"},
 {name:"value",type:"uint256"},{name:"validAfter",type:"uint256"},{name:"validBefore",type:"uint256"},{name:"nonce",type:"bytes32"}]};
const rnd=()=>"0x"+[...crypto.getRandomValues(new Uint8Array(32))].map(b=>b.toString(16).padStart(2,"0")).join("");
async function v(base,net,o){
  const vb=BigInt(Math.floor(Date.now()/1000)+3600);
  const m={from:acct.address,to:PAYTO,value:BigInt(o.value??"1000"),validAfter:0n,validBefore:vb,nonce:o.nonce};
  let sig=await acct.signTypedData({domain:{name:"USDC",version:"2",chainId:CHAIN,verifyingContract:USDC},types,primaryType:"TransferWithAuthorization",message:m});
  if(o.badSig) sig="0x"+"00".repeat(65);
  const body={paymentPayload:{x402Version:2,accepted:{scheme:"exact",network:net},resource:o.rp,
    payload:{signature:sig,authorization:{from:m.from,to:m.to,value:o.value??"1000",validAfter:"0",validBefore:vb.toString(),nonce:o.nonce}}},
   paymentRequirements:{scheme:"exact",network:net,resource:o.rq,payTo:PAYTO,asset:USDC,
    amount:o.value??"1000",maxAmountRequired:o.value??"1000",maxTimeoutSeconds:60,description:"probe",mimeType:"application/json",extra:{name:"USDC",version:"2"}}};
  try{const r=await fetch(base+"/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body),signal:AbortSignal.timeout(20000)});
    return {status:r.status,body:await r.json()};}catch(e){return {status:0,body:{error:e.name}};}
}
const A="https://probe.invalid/resource-A", B="https://probe.invalid/resource-B";
const T=[["Coinbase CDP","https://x402.org/facilitator","eip155:84532"],
        ["Dexter","https://x402.dexter.cash","eip155:84532"],
        ["PayAI","https://facilitator.payai.network","base-sepolia"],
        ["DayDreams","https://facilitator.daydreams.systems","eip155:84532"]];
console.log("x402 facilitator conformance survey — Base Sepolia — /verify only\n");
for(const [name,base,net] of T){
  const bad=await v(base,net,{rq:A,rp:A,nonce:rnd(),badSig:true});
  const over=await v(base,net,{rq:A,rp:A,nonce:rnd(),value:"999999999999"});
  const ctrl=await v(base,net,{rq:A,rp:A,nonce:rnd()});
  const i3=await v(base,net,{rq:B,rp:A,nonce:rnd()});
  const n=rnd(); const [a,b]=await Promise.all([v(base,net,{rq:A,rp:A,nonce:n}),v(base,net,{rq:A,rp:A,nonce:n})]);
  const sane=bad.body.isValid===false&&over.body.isValid===false, ok=ctrl.body.isValid===true;
  console.log(`── ${name}`);
  console.log(`   controls sane=${sane}  control accepted=${ok}`);
  if(!sane||!ok) console.log(`   I3 UNKNOWN  I4 UNKNOWN   (${ctrl.body.invalidReason??bad.body.invalidReason??ctrl.body.error??"?"})`);
  else console.log(`   I3 ${i3.body.isValid===true?"FAIL":"PASS"}     I4 ${a.body.isValid===true&&b.body.isValid===true?"FAIL":"PASS"}`);
  console.log("");
}
