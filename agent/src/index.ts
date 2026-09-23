import 'dotenv/config';
import cron from 'node-cron';
import { VigiloMCPClient, VigiloEvent, parseTransports } from './collectors/mcp';
import { analyzeEvents, signalDedupHash, Signal } from './agents/analyst';
import { SlackAlerter } from './slack/alerter';
import type { Logger } from 'pino';
import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
});

function requireEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`Missing required env var: ${key}`);
  return v;
}

// In-process dedup: hash → expiry timestamp
const dedupCache = new Map<string, number>();
const DEDUP_TTL_MS = parseInt(process.env.SIGNAL_COOLDOWN_MS ?? String(60 * 60 * 1000)); // 1h default

function isDuplicate(signal: Signal): boolean {
  const hash = signalDedupHash(signal.category, signal.title, signal.server);
  const expiry = dedupCache.get(hash);
  if (expiry && Date.now() < expiry) return true;
  dedupCache.set(hash, Date.now() + DEDUP_TTL_MS);
  return false;
}

export interface ScanClient {
  readonly serverLabel: string;
  getAllEvents(since: Date, severity?: string, limit?: number): Promise<VigiloEvent[]>;
}

export interface ScanAlerter {
  postSignal(signal: Signal, events: { resource: string; action: string; process?: string; server?: string }[]): Promise<string>;
  postScanSummary(eventsAnalyzed: number, signalCount: number, servers?: string[]): Promise<void>;
  postScanFailure(eventsAnalyzed: number, reason: string, servers?: string[]): Promise<void>;
}

export interface ScanDeps {
  clients: ScanClient[];
  alerter: ScanAlerter;
  lookbackMins: number;
  analyze?: (events: VigiloEvent[], servers: string[]) => Promise<Signal[]>;
  log?: Logger;
}

export async function runScan(deps: ScanDeps): Promise<void> {
  const { clients, alerter, lookbackMins, analyze = analyzeEvents, log = logger } = deps;
  const servers = clients.map(c => c.serverLabel);
  const since = new Date(Date.now() - lookbackMins * 60 * 1000);
  log.info({ since, servers }, 'scan started');

  // Fetch events from all daemons in parallel
  const perServerEvents = await Promise.allSettled(
    clients.map(c => c.getAllEvents(since, 'medium')),
  );

  const allEvents: VigiloEvent[] = [];
  const fetchFailures: string[] = [];
  for (let i = 0; i < clients.length; i++) {
    const result = perServerEvents[i];
    if (result.status === 'fulfilled') {
      allEvents.push(...result.value);
    } else {
      log.error({ server: clients[i].serverLabel, err: result.reason }, 'failed to fetch events');
      fetchFailures.push(clients[i].serverLabel);
    }
  }

  log.info({ eventCount: allEvents.length }, 'events aggregated');

  if (allEvents.length === 0) {
    if (fetchFailures.length > 0) {
      await alerter.postScanFailure(0, `could not fetch events from: ${fetchFailures.join(', ')}`, servers);
      return;
    }
    await alerter.postScanSummary(0, 0, servers);
    return;
  }

  let signals: Signal[];
  try {
    signals = await analyze(allEvents, servers);
  } catch (err) {
    // The scan did not complete. Say so — an empty signal list here would be
    // posted as a clean bill of health for a window nothing ever read.
    log.error({ err }, 'analysis failed');
    await alerter.postScanFailure(allEvents.length, (err as Error)?.message ?? 'unknown error', servers);
    return;
  }

  let posted = 0;
  for (const signal of signals) {
    if (isDuplicate(signal)) {
      log.info({ category: signal.category, title: signal.title }, 'signal suppressed (dedup)');
      continue;
    }
    const evidence = (signal.evidenceIndices ?? [])
      .map(i => allEvents[i])
      .filter(Boolean)
      .map(e => ({ resource: e.resource, action: e.action, process: e.process, server: e.server }));

    await alerter.postSignal(signal, evidence);
    log.info({ signalId: signal.id, severity: signal.severity, title: signal.title }, 'signal posted');
    posted++;
  }

  if (fetchFailures.length > 0) {
    await alerter.postScanFailure(
      allEvents.length,
      `partial scan: could not fetch events from ${fetchFailures.join(', ')}`,
      servers,
    );
    return;
  }

  await alerter.postScanSummary(allEvents.length, posted, servers);
}

async function main() {
  const slackToken   = requireEnv('SLACK_BOT_TOKEN');
  const alertChannel = requireEnv('VIGILO_ALERT_CHANNEL');
  const scanSchedule = process.env.SCAN_CRON ?? '*/5 * * * *';
  const lookbackMins = parseInt(process.env.LOOKBACK_MINUTES ?? '6');

  const transports = parseTransports();
  logger.info({ servers: transports.map(t => t.label) }, 'connecting to vigilo daemons');

  // Connect all clients in parallel
  const clients = await Promise.all(
    transports.map(async ({ label, transport }) => {
      const c = new VigiloMCPClient(label);
      await c.connect(transport);
      logger.info({ server: label, transport: transport.type }, 'connected');
      return c;
    }),
  );

  const alerter = new SlackAlerter(slackToken, alertChannel);

  const scan = () => runScan({ clients, alerter, lookbackMins });

  await scan();
  cron.schedule(scanSchedule, () => { scan(); });
  logger.info({ schedule: scanSchedule }, 'vigilo agent running');
}

if (require.main === module) {
  main().catch(err => {
    console.error('Fatal:', err);
    process.exit(1);
  });
}
