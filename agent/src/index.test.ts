import { test } from 'node:test';
import assert from 'node:assert/strict';
import pino from 'pino';
import { runScan, ScanClient } from './index';
import { SlackAlerter } from './slack/alerter';
import { AnalysisParseError, Signal } from './agents/analyst';
import { VigiloEvent } from './collectors/mcp';

const log = pino({ level: 'silent' });

interface PostedMessage { text?: string; blocks?: unknown }

// Drives the real SlackAlerter so the assertions run against the text an
// operator would actually read, not against a stand-in.
function captureAlerter(): { alerter: SlackAlerter; posted: PostedMessage[] } {
  const posted: PostedMessage[] = [];
  const alerter = new SlackAlerter('xoxb-test', '#vigilo');
  (alerter as unknown as { client: unknown }).client = {
    chat: {
      postMessage: async (args: PostedMessage) => {
        posted.push(args);
        return { ts: `${posted.length}` };
      },
    },
  };
  return { alerter, posted };
}

const CLEAN_SCAN_MARKERS = [':white_check_mark:', 'no threats detected'];

function assertNoCleanScan(posted: PostedMessage[]): void {
  for (const msg of posted) {
    for (const marker of CLEAN_SCAN_MARKERS) {
      assert.ok(
        !(msg.text ?? '').includes(marker),
        `a failed scan must never post "${marker}" — got: ${msg.text}`,
      );
    }
  }
}

function event(id: number, over: Partial<VigiloEvent> = {}): VigiloEvent {
  return {
    id,
    source: 'file_access',
    timestamp: '2026-09-23T00:00:00Z',
    action: 'read',
    resource: `/var/log/noise-${id}.log`,
    severity: 'info',
    server: 'prod-1',
    ...over,
  };
}

function client(events: VigiloEvent[], label = 'prod-1'): ScanClient {
  return { serverLabel: label, getAllEvents: async () => events };
}

let titleSeq = 0;
function signal(over: Partial<Signal> = {}): Signal {
  titleSeq++;
  return {
    id: `sig-${titleSeq}`,
    severity: 'critical',
    category: 'key_exfiltration',
    title: `Unexpected keystore read ${titleSeq}`,
    description: 'node read the keystore.',
    suggestedAction: 'Rotate the key',
    evidenceIndices: [0],
    detectedAt: new Date('2026-09-23T00:00:00Z'),
    server: 'prod-1',
    ...over,
  };
}

// ── #32: a scan that could not be analysed must not read as clean ────────────

test('a parse failure is reported as a failed scan, not as zero signals', async () => {
  const { alerter, posted } = captureAlerter();
  await runScan({
    clients: [client([event(1), event(2)])],
    alerter,
    lookbackMins: 6,
    analyze: async () => { throw new AnalysisParseError('no parseable JSON array'); },
    log,
  });

  assert.equal(posted.length, 1);
  assertNoCleanScan(posted);
  assert.match(posted[0].text ?? '', /INCOMPLETE/);
  assert.match(posted[0].text ?? '', /2 events collected/);
  assert.match(posted[0].text ?? '', /unchecked, not clear/);
});

test('any failed analysis is reported, not only parse failures', async () => {
  const { alerter, posted } = captureAlerter();
  await runScan({
    clients: [client([event(1)])],
    alerter,
    lookbackMins: 6,
    analyze: async () => { throw new Error('529 overloaded'); },
    log,
  });

  assertNoCleanScan(posted);
  assert.match(posted[0].text ?? '', /529 overloaded/);
});

test('a genuine no-threat scan still posts the clean summary', async () => {
  const { alerter, posted } = captureAlerter();
  await runScan({
    clients: [client([event(1)])],
    alerter,
    lookbackMins: 6,
    analyze: async () => [],
    log,
  });

  assert.equal(posted.length, 1);
  assert.match(posted[0].text ?? '', /1 events, no threats detected/);
});

test('an empty event window still posts the clean summary', async () => {
  const { alerter, posted } = captureAlerter();
  await runScan({ clients: [client([])], alerter, lookbackMins: 6, analyze: async () => [], log });
  assert.match(posted[0].text ?? '', /0 events, no threats detected/);
});

test('a posted signal suppresses the clean summary', async () => {
  const { alerter, posted } = captureAlerter();
  await runScan({
    clients: [client([event(1), event(2), event(3)])],
    alerter,
    lookbackMins: 6,
    analyze: async () => [signal()],
    log,
  });

  assert.equal(posted.length, 1);
  assert.match(JSON.stringify(posted[0].blocks), /Unexpected keystore read/);
});

test('a partial fetch can still alert but cannot claim the scan was clean', async () => {
  const { alerter, posted } = captureAlerter();
  const failing: ScanClient = {
    serverLabel: 'prod-2',
    getAllEvents: async () => { throw new Error('connection refused'); },
  };
  let seen = 0;
  await runScan({
    clients: [client([event(1), event(2)]), failing],
    alerter,
    lookbackMins: 6,
    analyze: async (events) => { seen = events.length; return []; },
    log,
  });

  assert.equal(seen, 2);
  assertNoCleanScan(posted);
  assert.match(posted[0].text ?? '', /INCOMPLETE/);
  assert.match(posted[0].text ?? '', /prod-2/);
});

test('if every event fetch fails, report an incomplete scan instead of clean zero', async () => {
  const { alerter, posted } = captureAlerter();
  const failing: ScanClient = {
    serverLabel: 'prod-1',
    getAllEvents: async () => { throw new Error('connection refused'); },
  };
  await runScan({ clients: [failing], alerter, lookbackMins: 6, log });

  assert.equal(posted.length, 1);
  assertNoCleanScan(posted);
  assert.match(posted[0].text ?? '', /INCOMPLETE/);
  assert.match(posted[0].text ?? '', /prod-1/);
});
