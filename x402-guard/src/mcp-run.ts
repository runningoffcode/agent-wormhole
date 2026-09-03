#!/usr/bin/env node
// src/mcp-run.ts
/**
 * The bin. All it does is start the stdio loop — the separation exists so that
 * `wormhole-x402/mcp` can be imported (for tests, or to mount the handler
 * elsewhere) without a side effect, while `npx wormhole-x402-mcp` just runs.
 */
import { serve } from "./mcp.js";

serve();
