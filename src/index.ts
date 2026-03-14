#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createAGAServer } from './server.js';

async function main() {
  const server = await createAGAServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AGA MCP Server v2.0.0 running on stdio');
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
