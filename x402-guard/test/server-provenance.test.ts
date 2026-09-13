import {describe,it,expect,vi} from "vitest";
import {PassThrough} from "node:stream";
import type {IncomingMessage,ServerResponse} from "node:http";
import {privateKeyToAccount} from "viem/accounts";
import {EIP3009} from "../src/evm.js";
import {createVerifyHandler,type ServerOptions} from "../src/server.js";
const account=privateKeyToAccount(`0x${"11".repeat(32)}`);
const asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",to="0x2222222222222222222222222222222222222222",nonce=`0x${"ab".repeat(32)}` as `0x${string}`;
async function request(provenance:string,opts:ServerOptions={}) {
  const message={from:account.address,to,value:1000000n,validAfter:0n,validBefore:0n,nonce};
  const signature=await account.signTypedData({domain:{name:"USD Coin",version:"2",chainId:8453,verifyingContract:asset},types:EIP3009.TYPES,primaryType:EIP3009.PRIMARY_TYPE,message});
  const body={network:"eip155:8453",quote:{network:"eip155:8453",asset,payTo:to,amount:"1000000"},payload:{signature,assetTransferMethod:"eip3009",authorization:{...message,value:"1000000",validAfter:"0",validBefore:"0"}}};
  const req=new PassThrough() as unknown as IncomingMessage;
  req.method="POST";req.url="/v1/verify";req.headers={"x-quote-provenance":provenance};
  let output="";
  const res={writeHead:()=>{},setHeader:()=>{},end:(data:string)=>{output=data;}} as unknown as ServerResponse;
  const done=createVerifyHandler(opts)(req,res);
  (req as unknown as PassThrough).end(JSON.stringify(body));await done;
  return JSON.parse(output);
}
describe("HTTP provenance trust boundary",()=>{
 it.each(["merchant_signed","independent_fetch","facilitator_held"])("ignores caller assertion %s",async label=>{
   const meter=vi.fn();const result=await request(label,{meter});
   expect(result.receipt.quote_provenance).toBe("caller_asserted");expect(result.billable).toBe(false);expect(meter).not.toHaveBeenCalled();
 });
 it("uses evidence supplied by a trusted server resolver",async()=>{
   const result=await request("caller_asserted",{resolveQuoteProvenance:()=>"merchant_signed"});
   expect(result.receipt.quote_provenance).toBe("merchant_signed");expect(result.billable).toBe(true);
 });
 it("abstains without a receipt if evidence verification fails",async()=>{
   const result=await request("merchant_signed",{resolveQuoteProvenance:()=>{throw new Error("signature invalid");}});
   expect(result.decision).toBe("abstain");expect(result.receipt).toBeUndefined();expect(result.signature).toBeUndefined();
 });
});
