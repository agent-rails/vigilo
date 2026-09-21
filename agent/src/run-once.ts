/**
 * One-shot scan: fetch events from the live daemon and run Claude analysis.
 * Run: npx ts-node src/run-once.ts
 */
import 'dotenv/config';
import { VigiloMCPClient, MCPTransport } from './collectors/mcp';
import { analyzeEvents } from './agents/analyst';
import pino from 'pino';

const logger = pino({
  transport: { target: 'pino-pretty', options: { colorize: true } },
});

async function main() {
  const mcpURL = process.env.VIGILO_MCP_URL ?? 'http://127.0.0.1:57070';
  const lookback = parseInt(process.env.LOOKBACK_MINUTES ?? '60');

  logger.info({ mcpURL, lookback }, 'connecting to vigilo daemon');

  const transport: MCPTransport = { type: 'http', url: mcpURL, token: process.env.VIGILO_MCP_TOKEN };
  const client = new VigiloMCPClient('local');
  await client.connect(transport);
  logger.info('connected');

  const since = new Date(Date.now() - lookback * 60 * 1000);
  const events = await client.getAllEvents(since, 'medium');
  logger.info({ count: events.length, since }, 'events fetched');

  if (events.length === 0) {
    logger.info('no events — nothing to analyze');
    await client.disconnect();
    return;
  }

  // Show what was fetched
  for (const e of events) {
    logger.info({ severity: e.severity, source: e.source, action: e.action, resource: e.resource }, 'event');
  }

  logger.info('running Claude analysis...');
  const signals = await analyzeEvents(events, ['local']);

  if (signals.length === 0) {
    logger.info('Claude found no threats in the event window');
  } else {
    logger.info({ count: signals.length }, 'signals detected');
    const bar = '─'.repeat(60);
    for (const s of signals) {
      console.log(`\n${bar}`);
      console.log(`SEVERITY : ${s.severity.toUpperCase()}`);
      console.log(`CATEGORY : ${s.category}`);
      console.log(`TITLE    : ${s.title}`);
      console.log(`DETAIL   : ${s.description}`);
      console.log(`ACTION   : ${s.suggestedAction}`);
      console.log(`EVIDENCE : event indices [${s.evidenceIndices.join(', ')}]`);
      console.log(bar);
    }
  }

  await client.disconnect();
}

main().catch(err => {
  logger.error({ err }, 'run-once failed');
  process.exit(1);
});
