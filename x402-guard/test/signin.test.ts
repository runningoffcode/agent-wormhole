/**
 * Sign-in requests held to the site the agent contacted (0.10.0, src/signin.ts).
 *
 * The case is V12's third critical x402 SDK finding: a server relays another
 * site's fresh Sign-In-With-X challenge, and the agent signs a login for that
 * site. The guarded signers refuse message signing by default; these tests hold
 * the check an application gets when it allows message signing, and hold every
 * message that is not a sign-in request to its old answer.
 */

import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { verifyMessage, type Hex } from "viem";
import {
  Keypair,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
  SystemProgram,
} from "@solana/web3.js";
import { guardEvmSigner, type EvmPaymentQuote } from "../src/evm.js";
import {
  guardSigner,
  inspectSignIn,
  inspectSignInInput,
  isSignInText,
  type PaymentQuote,
} from "../src/index.js";

const ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const DATA = "https://data.example";

function siwe(domain: string, uri: string, opts: { scheme?: string; chain?: string; lines?: string[] } = {}): string {
  const head = `${opts.scheme ? `${opts.scheme}://` : ""}${domain} wants you to sign in with your ${opts.chain ?? "Ethereum"} account:`;
  return [
    head,
    ADDRESS,
    "",
    "Sign in to the API",
    "",
    `URI: ${uri}`,
    "Version: 1",
    "Chain ID: 8453",
    "Nonce: 32891756",
    "Issued At: 2026-10-22T12:00:00Z",
    ...(opts.lines ?? []),
  ].join("\n");
}

const codes = (v: { findings: { code: string }[] }) => v.findings.map((f) => f.code);

describe("inspectSignIn: what is a sign-in request", () => {
  it("a plain message is not one, and is allowed as before", () => {
    const v = inspectSignIn("hello, merchant", DATA);
    expect(v).toMatchObject({ decision: "allow", signIn: false });
  });

  it("a login for the site contacted is allowed", () => {
    const v = inspectSignIn(siwe("data.example", "https://data.example/login"), DATA);
    expect(v).toMatchObject({ decision: "allow", signIn: true });
  });

  it("the relay: a login for another site is refused (X402-601)", () => {
    const v = inspectSignIn(siwe("app.example", "https://app.example/login"), DATA);
    expect(v.decision).toBe("refuse");
    expect(codes(v)).toEqual(["X402-601"]);
  });

  it("the right domain with another site's URI is refused", () => {
    expect(codes(inspectSignIn(siwe("data.example", "https://app.example/login"), DATA))).toEqual(["X402-601"]);
  });

  it("another site's domain with the contacted site's URI is refused — the domain is what the target checks", () => {
    // A SIWE verifier at app.example accepts a message whose domain is
    // app.example; the URI line pointing at the site the agent contacted does
    // not make it a login there. The domain comparison alone catches this.
    expect(codes(inspectSignIn(siwe("app.example", "https://data.example/login"), DATA))).toEqual(["X402-601"]);
  });

  it("another scheme in the header or the URI is refused", () => {
    expect(codes(inspectSignIn(siwe("data.example", "https://data.example/", { scheme: "http" }), DATA))).toEqual(["X402-601"]);
    expect(codes(inspectSignIn(siwe("data.example", "http://data.example/"), DATA))).toEqual(["X402-601"]);
  });

  it("a port is part of the site", () => {
    const origin = "https://data.example:8443";
    expect(inspectSignIn(siwe("data.example:8443", "https://data.example:8443/"), origin).decision).toBe("allow");
    expect(codes(inspectSignIn(siwe("data.example", "https://data.example/"), origin))).toEqual(["X402-601"]);
  });

  it("CRLF line endings are refused, as the siwe library and the Wallet Standard's parser refuse them", () => {
    const v = inspectSignIn(siwe("data.example", "https://data.example/").replace(/\n/g, "\r\n"), DATA);
    expect(codes(v)).toEqual(["X402-602"]);
  });

  it("a Sign-In-With-Solana message is held to the same rule", () => {
    expect(inspectSignIn(siwe("data.example", "https://data.example/", { chain: "Solana" }), DATA).decision).toBe("allow");
    expect(codes(inspectSignIn(siwe("app.example", "https://app.example/", { chain: "Solana" }), DATA))).toEqual(["X402-601"]);
  });
});

describe("inspectSignIn: no known site, and malformed requests, are refused (X402-602)", () => {
  it("no origin: every sign-in request is refused, a plain message is not", () => {
    expect(codes(inspectSignIn(siwe("data.example", "https://data.example/"), undefined))).toEqual(["X402-602"]);
    expect(inspectSignIn("hello", undefined).decision).toBe("allow");
  });

  it("the quote's resource stands in for a missing origin", () => {
    expect(inspectSignIn(siwe("data.example", "https://data.example/"), undefined, "https://data.example/report").decision).toBe("allow");
    expect(codes(inspectSignIn(siwe("app.example", "https://app.example/"), undefined, "https://data.example/report"))).toEqual(["X402-601"]);
  });

  it("an origin that is not an http(s) URL is no origin", () => {
    for (const bad of ["data.example", "ftp://data.example", "https://user:pw@data.example", "", "   "]) {
      expect(codes(inspectSignIn(siwe("data.example", "https://data.example/"), bad)), bad).toEqual(["X402-602"]);
    }
  });

  it("an origin given as a function is read at call time", () => {
    let site = DATA;
    const origin = () => site;
    expect(inspectSignIn(siwe("data.example", "https://data.example/"), origin).decision).toBe("allow");
    site = "https://other.example";
    expect(codes(inspectSignIn(siwe("data.example", "https://data.example/"), origin))).toEqual(["X402-601"]);
  });

  const malformed: [string, string][] = [
    ["the header not on the first line", "Hi!\n" + siwe("data.example", "https://data.example/")],
    ["a BOM before the header", "﻿" + siwe("data.example", "https://data.example/")],
    ["two headers", siwe("data.example", "https://data.example/") + "\napp.example wants you to sign in with your Ethereum account:"],
    ["no URI line", siwe("data.example", "https://data.example/").replace(/\nURI: [^\n]+/, "")],
    ["two URI lines", siwe("data.example", "https://data.example/", { lines: ["URI: https://app.example/"] })],
    ["a lowercase second URI line", siwe("data.example", "https://data.example/", { lines: ["uri: https://app.example/"] })],
    ["a URI that does not parse", siwe("data.example", "not a url")],
    ["userinfo in the domain", siwe("data.example@app.example", "https://data.example/")],
    ["a path in the domain", siwe("data.example/x", "https://data.example/")],
  ];
  for (const [name, text] of malformed) {
    it(name, () => {
      const v = inspectSignIn(text, DATA);
      expect(v.decision, name).toBe("refuse");
      expect(codes(v)).toEqual(["X402-602"]);
    });
  }

  it("lookalike and invisible characters in the header are still recognised, then refused", () => {
    const zw = siwe("app.example", "https://app.example/").replace("wants you", "wants​ you");
    const wide = siwe("app.example", "https://app.example/").replace("sign in", "ｓｉｇｎ ｉｎ");
    for (const text of [zw, wide]) {
      expect(isSignInText(text)).toBe(true);
      expect(inspectSignIn(text, DATA).decision).toBe("refuse");
    }
  });

  it("the fields of a request without its header are recognised, then refused", () => {
    const text = "Log in please\nURI: https://app.example/\nNonce: 1234";
    expect(isSignInText(text)).toBe(true);
    expect(codes(inspectSignIn(text, DATA))).toEqual(["X402-602"]);
  });
});

describe("inspectSignIn: the shapes a message reaches a signer in", () => {
  const text = siwe("app.example", "https://app.example/");
  const bytes = new TextEncoder().encode(text);
  const hex = ("0x" + [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")) as Hex;
  for (const [name, arg] of [
    ["a string", text],
    ["bytes", bytes],
    ["viem's { message }", { message: text }],
    ["viem's { message: { raw: hex } }", { message: { raw: hex } }],
    ["viem's { message: { raw: bytes } }", { message: { raw: bytes } }],
  ] as [string, unknown][]) {
    it(name, () => {
      expect(codes(inspectSignIn(arg, DATA)), name).toEqual(["X402-601"]);
    });
  }

  it("an argument that cannot be read as a message is refused, not signed unread", () => {
    expect(codes(inspectSignIn({ nonsense: true }, DATA))).toEqual(["X402-602"]);
    expect(codes(inspectSignIn(42, DATA))).toEqual(["X402-602"]);
  });
});

describe("inspectSignInInput: the Wallet Standard signIn input", () => {
  it("allows the site contacted, with or without a uri", () => {
    expect(inspectSignInInput({ domain: "data.example", uri: "https://data.example/login" }, DATA).decision).toBe("allow");
    expect(inspectSignInInput({ domain: "data.example" }, DATA).decision).toBe("allow");
  });

  it("refuses another site's domain or uri (X402-601)", () => {
    expect(codes(inspectSignInInput({ domain: "app.example" }, DATA))).toEqual(["X402-601"]);
    expect(codes(inspectSignInInput({ domain: "data.example", uri: "https://app.example/" }, DATA))).toEqual(["X402-601"]);
  });

  it("refuses no domain, a malformed one, no input and no known site (X402-602)", () => {
    expect(codes(inspectSignInInput({}, DATA))).toEqual(["X402-602"]);
    expect(codes(inspectSignInInput({ domain: "a@b.example" }, DATA))).toEqual(["X402-602"]);
    expect(codes(inspectSignInInput(undefined, DATA))).toEqual(["X402-602"]);
    expect(codes(inspectSignInInput({ domain: "data.example" }, undefined))).toEqual(["X402-602"]);
  });
});

// --- the EVM signer ------------------------------------------------------------

describe("guardEvmSigner and sign-in requests", () => {
  const quote: EvmPaymentQuote = {
    network: "eip155:8453",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    payTo: "0x1111111111111111111111111111111111111111",
    amount: "10000",
  };

  function fakeSigner() {
    const calls: string[] = [];
    return {
      calls,
      async signMessage(_p: unknown) {
        calls.push("signMessage");
        return "0xsigned";
      },
    };
  }

  it("by default every message, a login included, is refused as before", async () => {
    const s = fakeSigner();
    const g = guardEvmSigner(s, () => quote, { origin: DATA });
    await expect(g.signMessage({ message: siwe("data.example", "https://data.example/") })).rejects.toThrow(/could not read an x402 payment/);
    expect(s.calls).toEqual([]);
  });

  it("with signMessage allowed: the site's login signs, a relayed one does not, a plain message signs", async () => {
    const s = fakeSigner();
    const g = guardEvmSigner(s, () => quote, { allow: ["signMessage"], origin: DATA });
    await expect(g.signMessage({ message: siwe("data.example", "https://data.example/") })).resolves.toBe("0xsigned");
    await expect(g.signMessage({ message: siwe("app.example", "https://app.example/") })).rejects.toThrow(/X402-601/);
    await expect(g.signMessage("hello")).resolves.toBe("0xsigned");
    expect(s.calls).toEqual(["signMessage", "signMessage"]);
  });

  it("with signMessage allowed and no site known: logins refused, plain messages signed", async () => {
    const s = fakeSigner();
    const g = guardEvmSigner(s, () => quote, { allow: ["signMessage"] });
    await expect(g.signMessage({ message: siwe("data.example", "https://data.example/") })).rejects.toThrow(/X402-602/);
    await expect(g.signMessage({ message: "hello" })).resolves.toBe("0xsigned");
  });

  it("the quote's resource is the site when no origin is given", async () => {
    const s = fakeSigner();
    const g = guardEvmSigner(s, () => ({ ...quote, resource: "https://data.example/report" }), { allow: ["signMessage"] });
    await expect(g.signMessage({ message: siwe("data.example", "https://data.example/") })).resolves.toBe("0xsigned");
    await expect(g.signMessage({ message: siwe("app.example", "https://app.example/") })).rejects.toThrow(/X402-601/);
  });

  it("a real viem account behind the guard: the relayed login is never signed", async () => {
    const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex);
    const g = guardEvmSigner(account, () => quote, { allow: ["signMessage"], origin: DATA });
    await expect(g.signMessage({ message: siwe("app.example", "https://app.example/") })).rejects.toThrow(/X402-601/);
    const sig = await g.signMessage({ message: siwe("data.example", "https://data.example/") });
    expect(sig).toMatch(/^0x[0-9a-f]{130}$/);
  });
});

// --- the Solana signer ---------------------------------------------------------

describe("guardSigner and sign-in requests", () => {
  const payer = Keypair.generate();
  const quote: PaymentQuote = {
    payTo: Keypair.generate().publicKey.toBase58(),
    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    amount: "1000000",
  };
  const enc = (t: string) => new TextEncoder().encode(t);
  const txBytes = () =>
    new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: PublicKey.default.toBase58(),
      instructions: [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: Keypair.generate().publicKey, lamports: 1 })],
    })
      .compileToV0Message()
      .serialize();

  function fakeWallet() {
    const calls: string[] = [];
    return {
      calls,
      async signTransaction(tx: VersionedTransaction) {
        return tx;
      },
      async signMessage(_m: unknown) {
        calls.push("signMessage");
        return { signature: new Uint8Array(64) };
      },
      async signMessages(_m: unknown[]) {
        calls.push("signMessages");
        return [];
      },
      async signIn(_i: unknown) {
        calls.push("signIn");
        return { signature: new Uint8Array(64) };
      },
    };
  }

  it("by default signMessage and signIn are refused as before", async () => {
    const w = fakeWallet();
    const g = guardSigner(w, () => quote, { origin: DATA });
    await expect(g.signMessage(enc(siwe("data.example", "https://data.example/", { chain: "Solana" })))).rejects.toThrow(/does not know how to check it/);
    await expect(g.signIn({ domain: "data.example" })).rejects.toThrow(/does not know how to check it/);
    expect(w.calls).toEqual([]);
  });

  it("with signMessage allowed: the site's login signs, a relayed one does not, a plain message signs", async () => {
    const w = fakeWallet();
    const g = guardSigner(w, () => quote, { allow: ["signMessage"], origin: DATA });
    await g.signMessage(enc(siwe("data.example", "https://data.example/", { chain: "Solana" })));
    await expect(g.signMessage(enc(siwe("app.example", "https://app.example/", { chain: "Solana" })))).rejects.toThrow(/X402-601/);
    await g.signMessage(enc("hello"));
    expect(w.calls).toEqual(["signMessage", "signMessage"]);
  });

  it("transaction bytes are still refused as a message", async () => {
    const g = guardSigner(fakeWallet(), () => quote, { allow: ["signMessage"], origin: DATA });
    await expect(g.signMessage(txBytes())).rejects.toThrow(/deserialize as a Solana transaction message/);
  });

  it("signMessages checks every message in the array — transaction bytes and relayed logins included", async () => {
    const w = fakeWallet();
    const g = guardSigner(w, () => quote, { allow: ["signMessages"], origin: DATA });
    await expect(g.signMessages([enc("hello"), txBytes()])).rejects.toThrow(/deserialize as a Solana transaction message/);
    await expect(g.signMessages([enc(siwe("app.example", "https://app.example/", { chain: "Solana" }))])).rejects.toThrow(/X402-601/);
    await g.signMessages([enc("hello"), enc("world")]);
    expect(w.calls).toEqual(["signMessages"]);
  });

  it("a base64 string carrying a relayed login is refused whichever reading the wallet takes", async () => {
    const g = guardSigner(fakeWallet(), () => quote, { allow: ["signMessage"], origin: DATA });
    const b64 = Buffer.from(siwe("app.example", "https://app.example/", { chain: "Solana" })).toString("base64");
    await expect(g.signMessage(b64)).rejects.toThrow(/X402-601/);
  });

  it("with signIn allowed: the input must name the site contacted", async () => {
    const w = fakeWallet();
    const g = guardSigner(w, () => quote, { allow: ["signIn"], origin: DATA });
    await g.signIn({ domain: "data.example", uri: "https://data.example/login" });
    await expect(g.signIn({ domain: "app.example" })).rejects.toThrow(/X402-601/);
    await expect(g.signIn({})).rejects.toThrow(/X402-602/);
    await expect(g.signIn(undefined)).rejects.toThrow(/X402-602/);
    expect(w.calls).toEqual(["signIn"]);
  });
});

// --- what a wallet signs, every input, and origins (AWG-010-01, -02, -03, -06) ---

const hexOf = (t: string) => ("0x" + Buffer.from(t).toString("hex")) as Hex;

describe("an EVM signer signs the message that was checked", () => {
  const quote: EvmPaymentQuote = {
    network: "eip155:8453",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    payTo: "0x1111111111111111111111111111111111111111",
    amount: "10000",
  };
  const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex);
  const evil = siwe("app.example", "https://app.example/");

  function recordingSigner() {
    const seen: unknown[] = [];
    return {
      seen,
      async signMessage(p: unknown) {
        seen.push(p);
        return "0xsigned";
      },
    };
  }

  it.each([
    ["a string", evil],
    ["raw hex", { raw: hexOf(evil) }],
    ["raw bytes", { raw: new TextEncoder().encode(evil) }],
  ] as [string, unknown][])("a relayed login in `message` (%s) beside a harmless top-level `raw` is never signed", async (_name, message) => {
    const g = guardEvmSigner(account, () => quote, { allow: ["signMessage"], origin: DATA });
    await expect(g.signMessage({ message, raw: hexOf("hello") } as never)).rejects.toThrow(/X402-60[12]/);
  });

  it("and the other way round: a harmless `message` beside a login in `raw` is refused too", async () => {
    const s = recordingSigner();
    const g = guardEvmSigner(s, () => quote, { allow: ["signMessage"], origin: DATA });
    await expect(g.signMessage({ message: "hello", raw: hexOf(evil) } as never)).rejects.toThrow(/X402-602/);
    expect(s.seen).toEqual([]);
  });

  it("a top-level `raw` alone is no shape viem or ethers signs, and is refused", async () => {
    const g = guardEvmSigner(recordingSigner(), () => quote, { allow: ["signMessage"], origin: DATA });
    await expect(g.signMessage({ raw: hexOf("hello") } as never)).rejects.toThrow(/X402-602/);
  });

  it("a getter that changes `message` after the check: the signer gets what was checked", async () => {
    const s = recordingSigner();
    const g = guardEvmSigner(s, () => quote, { allow: ["signMessage"], origin: DATA });
    let reads = 0;
    const arg = {
      get message() {
        return ++reads === 1 ? "hello" : evil;
      },
    };
    await g.signMessage(arg);
    expect((s.seen[0] as { message: unknown }).message).toBe("hello");
  });

  it("bytes changed after the call never reach the signer: it signs a copy", async () => {
    let signed = "";
    const s = {
      async signMessage(p: unknown) {
        await new Promise((r) => setTimeout(r, 5));
        signed = new TextDecoder().decode(p as Uint8Array);
        return "0xsigned";
      },
    };
    const g = guardEvmSigner(s, () => quote, { allow: ["signMessage"], origin: DATA });
    const bytes = new TextEncoder().encode("hello");
    const pending = g.signMessage(bytes);
    bytes.set(new TextEncoder().encode(evil.slice(0, 5)));
    await pending;
    expect(signed).toBe("hello");
  });

  it("a real viem account signs exactly the bytes of the same-site login it was handed as raw", async () => {
    const g = guardEvmSigner(account, () => quote, { allow: ["signMessage"], origin: DATA });
    const login = siwe("data.example", "https://data.example/");
    const raw = new TextEncoder().encode(login);
    const signature = await g.signMessage({ message: { raw } });
    expect(await verifyMessage({ address: account.address, message: login, signature })).toBe(true);
  });
});

describe("a Solana wallet: every message shape and every argument", () => {
  const payer = Keypair.generate();
  const quote: PaymentQuote = {
    payTo: Keypair.generate().publicKey.toBase58(),
    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    amount: "1000000",
  };
  const enc = (t: string) => new TextEncoder().encode(t);
  const txBytes = () =>
    new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: PublicKey.default.toBase58(),
      instructions: [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: Keypair.generate().publicKey, lamports: 1 })],
    })
      .compileToV0Message()
      .serialize();
  const account = {
    address: payer.publicKey.toBase58(),
    publicKey: payer.publicKey.toBytes(),
    chains: ["solana:mainnet"],
    features: ["solana:signMessage", "solana:signIn"],
  };
  const relayed = () => enc(siwe("app.example", "https://app.example/", { chain: "Solana" }));

  function wallet() {
    const received: unknown[][] = [];
    return {
      received,
      async signTransaction(tx: VersionedTransaction) {
        return tx;
      },
      async signMessage(...inputs: unknown[]) {
        received.push(inputs);
        return inputs.map(() => ({ signature: new Uint8Array(64) }));
      },
      async signMessages(...inputs: unknown[]) {
        received.push(inputs);
        return [];
      },
      async signIn(...inputs: unknown[]) {
        received.push(inputs);
        return inputs.map(() => ({ signature: new Uint8Array(64) }));
      },
    };
  }

  it.each(["signMessage", "signMessages"])("transaction bytes inside a Wallet Standard input to %s are refused", async (method) => {
    const w = wallet();
    const g = guardSigner(w, () => quote, { allow: [method], origin: DATA });
    const input = { account, message: txBytes() };
    const call = method === "signMessage" ? g.signMessage(input) : g.signMessages([input]);
    await expect(call).rejects.toThrow(/deserialize as a Solana transaction message/);
    expect(w.received).toEqual([]);
  });

  it("a relayed login inside a Wallet Standard input is refused", async () => {
    const w = wallet();
    const g = guardSigner(w, () => quote, { allow: ["signMessage"], origin: DATA });
    await expect(g.signMessage({ account, message: relayed() })).rejects.toThrow(/X402-601/);
    expect(w.received).toEqual([]);
  });

  it("a second signMessage input carrying transaction bytes or another site's login is refused, the first unsigned too", async () => {
    for (const [second, pattern] of [
      [{ account, message: txBytes() }, /deserialize as a Solana transaction message/],
      [{ account, message: relayed() }, /X402-601/],
      [txBytes(), /deserialize as a Solana transaction message/],
    ] as [unknown, RegExp][]) {
      const w = wallet();
      const g = guardSigner(w, () => quote, { allow: ["signMessage"], origin: DATA });
      await expect(g.signMessage({ account, message: enc("hello") }, second)).rejects.toThrow(pattern);
      expect(w.received).toEqual([]);
    }
  });

  it("a second signIn input for another site is refused, and the first is not signed either", async () => {
    const w = wallet();
    const g = guardSigner(w, () => quote, { allow: ["signIn"], origin: DATA });
    await expect(
      g.signIn({ domain: "data.example", uri: "https://data.example/login" }, { domain: "app.example", uri: "https://app.example/login" }),
    ).rejects.toThrow(/X402-601/);
    await expect(g.signIn({ domain: "data.example" }, undefined)).rejects.toThrow(/X402-602/);
    await expect(g.signIn()).rejects.toThrow(/X402-602/);
    expect(w.received).toEqual([]);
    await g.signIn({ domain: "data.example" }, { domain: "data.example", uri: "https://data.example/login" });
    expect(w.received).toHaveLength(1);
  });

  it("arguments that cannot carry a message pass as they were: a display hint, a public key", async () => {
    const w = wallet();
    const g = guardSigner(w, () => quote, { allow: ["signMessage"], origin: DATA });
    const key = Keypair.generate().publicKey;
    await g.signMessage(enc("hello"), "utf8");
    await g.signMessage(enc("hello"), key);
    expect(w.received[0]?.[1]).toBe("utf8");
    expect(w.received[1]?.[1]).toBe(key);
  });

  it("the wallet signs a copy of the bytes that were checked", async () => {
    const w = wallet();
    const g = guardSigner(w, () => quote, { allow: ["signMessage"], origin: DATA });
    const bytes = enc("hello");
    await g.signMessage({ account, message: bytes });
    const handed = (w.received[0]?.[0] as { message: Uint8Array }).message;
    expect(handed).not.toBe(bytes);
    expect(new TextDecoder().decode(handed)).toBe("hello");
  });

  it("a getter on an input's message cannot swap it after the check", async () => {
    const w = wallet();
    const g = guardSigner(w, () => quote, { allow: ["signMessage"], origin: DATA });
    let reads = 0;
    const input = {
      account,
      get message() {
        return ++reads === 1 ? enc("hello") : txBytes();
      },
    };
    await g.signMessage(input);
    const handed = (w.received[0]?.[0] as { message: Uint8Array }).message;
    expect(new TextDecoder().decode(handed)).toBe("hello");
  });

  it("a getter on a signIn input cannot name one site to the check and another to the wallet", async () => {
    const w = wallet();
    const g = guardSigner(w, () => quote, { allow: ["signIn"], origin: DATA });
    let reads = 0;
    const input = {
      get domain() {
        return ++reads === 1 ? "data.example" : "app.example";
      },
    };
    await g.signIn(input);
    expect((w.received[0]?.[0] as { domain: string }).domain).toBe("data.example");
  });
});

describe("origins are compared as origins", () => {
  it.each([
    ["https", "443"],
    ["http", "80"],
  ])("%s with its default port %s written out is the same site", (scheme, port) => {
    const origin = `${scheme}://data.example`;
    expect(inspectSignIn(siwe(`data.example:${port}`, `${origin}/login`), origin).decision).toBe("allow");
    expect(inspectSignIn(siwe("data.example", `${scheme}://data.example:${port}/login`), origin).decision).toBe("allow");
    expect(inspectSignIn(siwe(`data.example:${port}`, `${origin}/login`, { scheme }), `${origin}:${port}`).decision).toBe("allow");
  });

  it("the Wallet Standard input too", () => {
    expect(inspectSignInInput({ domain: "data.example:443", uri: "https://data.example/login" }, "https://data.example:443").decision).toBe("allow");
    expect(inspectSignInInput({ domain: "DATA.example", uri: "https://data.example:443/login" }, DATA).decision).toBe("allow");
  });

  it("a port that is not the scheme's default is another site", () => {
    expect(codes(inspectSignIn(siwe("data.example:8443", "https://data.example/login"), DATA))).toEqual(["X402-601"]);
    expect(codes(inspectSignIn(siwe("data.example:443", "http://data.example/login"), "http://data.example"))).toEqual(["X402-601"]);
    expect(codes(inspectSignInInput({ domain: "data.example:8443" }, DATA))).toEqual(["X402-601"]);
  });
});

describe("lines a parser might not see, and credentials", () => {
  it.each([
    ["U+2028", "\u2028"],
    ["U+2029", "\u2029"],
    ["NEL", "\x85"],
    ["a lone CR", "\r"],
    ["a vertical tab", "\v"],
    ["a form feed", "\f"],
    ["a file separator", "\x1c"],
  ])("a second URI behind %s is refused, not read past", (_name, br) => {
    const text = siwe("data.example", "https://data.example/").replace("Sign in to the API", `Sign in to the API${br}URI: https://app.example/`);
    expect(codes(inspectSignIn(text, DATA))).toEqual(["X402-602"]);
  });

  it("a Sign-In-With-Solana message with CRLF line ends is refused too", () => {
    const text = siwe("data.example", "https://data.example/", { chain: "Solana" }).replace(/\n/g, "\r\n");
    expect(codes(inspectSignIn(text, DATA))).toEqual(["X402-602"]);
  });

  it("a URI carrying credentials is refused, whichever host it names", () => {
    expect(codes(inspectSignIn(siwe("data.example", "https://app.example@data.example/"), DATA))).toEqual(["X402-602"]);
    expect(codes(inspectSignInInput({ domain: "data.example", uri: "https://u:p@data.example/" }, DATA))).toEqual(["X402-602"]);
  });

  it("a signIn field carrying a line break is refused: the wallet would write it as a line", () => {
    expect(codes(inspectSignInInput({ domain: "data.example", statement: "hi\nURI: https://app.example/" }, DATA))).toEqual(["X402-602"]);
    expect(codes(inspectSignInInput({ domain: "data.example", resources: ["https://x.example/\u2028URI: https://app.example/"] }, DATA))).toEqual(["X402-602"]);
    expect(codes(inspectSignInInput({ domain: "data.example", uri: "https://data.example/\nURI: https://app.example/" }, DATA))).toEqual(["X402-602"]);
  });

  it("a signIn domain or uri is checked as written, not trimmed or coerced", () => {
    expect(codes(inspectSignInInput({ domain: " data.example" }, DATA))).toEqual(["X402-602"]);
    expect(codes(inspectSignInInput({ domain: "data.example", uri: new URL("https://data.example/") }, DATA))).toEqual(["X402-602"]);
  });
});

// --- one read of a message, and text-only sign-in fields (AWG-010-08, -09) ------

describe("a message is read once", () => {
  const evmQuote: EvmPaymentQuote = {
    network: "eip155:8453",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    payTo: "0x1111111111111111111111111111111111111111",
    amount: "10000",
  };
  const svmQuote: PaymentQuote = {
    payTo: Keypair.generate().publicKey.toBase58(),
    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    amount: "1000000",
  };
  const guards = () => {
    const signer = { async signTransaction(tx: VersionedTransaction) { return tx; }, async signMessage(x: unknown) { return x; } };
    return [
      { name: "evm", g: guardEvmSigner(signer, () => evmQuote, { allow: ["signMessage"], origin: DATA }), text: (t: string): unknown => t },
      { name: "solana", g: guardSigner(signer, () => svmQuote, { allow: ["signMessage"], origin: DATA }), text: (t: string): unknown => new TextEncoder().encode(t) },
    ];
  };

  it("a message getter runs once", async () => {
    for (const { name, g, text } of guards()) {
      let reads = 0;
      await g.signMessage({
        get message() {
          reads++;
          return text("hello");
        },
      } as never);
      expect(reads, name).toBe(1);
    }
  });

  it("a getter that would throw on a second read still signs", async () => {
    for (const { name, g, text } of guards()) {
      let reads = 0;
      const input = {
        get message() {
          if (++reads > 1) throw new Error("second read");
          return text("hello");
        },
      };
      await expect(g.signMessage(input as never), name).resolves.toBeDefined();
    }
  });
});

describe("every field a wallet writes into a sign-in message is text", () => {
  const svmQuote: PaymentQuote = {
    payTo: Keypair.generate().publicKey.toBase58(),
    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    amount: "1000000",
  };
  const otherUri = "Sign in.\n\nURI: https://app.example/login";

  it("a statement that would convert to another URI line is refused before the wallet is asked", async () => {
    const calls: unknown[] = [];
    const w = { async signTransaction(tx: VersionedTransaction) { return tx; }, async signIn(...i: unknown[]) { calls.push(i); return []; } };
    const g = guardSigner(w, () => svmQuote, { allow: ["signIn"], origin: DATA });
    for (const statement of [[[otherUri]], { toString: () => otherUri }]) {
      await expect(g.signIn({ domain: "data.example", statement })).rejects.toThrow(/X402-602/);
    }
    expect(calls).toEqual([]);
  });

  it.each(["address", "statement", "uri", "version", "chainId", "nonce", "issuedAt", "expirationTime", "notBefore", "requestId"])(
    "%s that is not text is refused",
    (field) => {
      for (const value of [["x"], 1, { toString: () => "x" }, null]) {
        expect(codes(inspectSignInInput({ domain: "data.example", [field]: value }, DATA)), `${field}=${String(value)}`).toEqual(["X402-602"]);
      }
    },
  );

  it("resources must be a list of text", () => {
    for (const resources of ["https://data.example/", [["https://data.example/"]], [1], [{ toString: () => "x" }]]) {
      expect(codes(inspectSignInInput({ domain: "data.example", resources }, DATA))).toEqual(["X402-602"]);
    }
  });

  it("an input whose every field is text signs as before", () => {
    const input = {
      domain: "data.example",
      address: Keypair.generate().publicKey.toBase58(),
      statement: "Sign in to the API",
      uri: "https://data.example/login",
      version: "1",
      chainId: "solana:mainnet",
      nonce: "32891756",
      issuedAt: "2026-10-22T12:00:00Z",
      expirationTime: "2026-10-22T13:00:00Z",
      notBefore: "2026-10-22T12:00:00Z",
      requestId: "r-1",
      resources: ["https://data.example/a", "https://data.example/b"],
    };
    expect(inspectSignInInput(input, DATA).decision).toBe("allow");
  });
});

