import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SlackAlerter } from './alerter';
import { Signal } from '../agents/analyst';

export interface PostedMessage { text?: string; blocks?: unknown }

export function captureAlerter(): { alerter: SlackAlerter; posted: PostedMessage[] } {
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

export const CLEAN_SCAN_MARKERS = [':white_check_mark:', 'no threats detected'];

export function signal(over: Partial<Signal> = {}): Signal {
  return {
    id: 'abc123',
    severity: 'critical',
    category: 'key_exfiltration',
    title: 'Unexpected read of wallet].json',
    description: 'node read the keystore.',
    suggestedAction: 'Rotate the key',
    evidenceIndices: [0],
    detectedAt: new Date('2026-09-23T00:00:00Z'),
    server: 'prod-1',
    ...over,
  };
}

test('postScanFailure never reads as a clean scan', async () => {
  const { alerter, posted } = captureAlerter();
  await alerter.postScanFailure(412, 'no parseable JSON array', ['prod-1', 'prod-2']);

  assert.equal(posted.length, 1);
  const text = posted[0].text ?? '';
  for (const marker of CLEAN_SCAN_MARKERS) {
    assert.ok(!text.includes(marker), `failure message must not contain "${marker}": ${text}`);
  }
  assert.match(text, /INCOMPLETE/);
  assert.match(text, /results may be partial/);
  assert.match(text, /412 events/);
  assert.match(text, /across 2 servers/);
});

test('postScanSummary still reports a genuine clean scan', async () => {
  const { alerter, posted } = captureAlerter();
  await alerter.postScanSummary(12, 0, ['prod-1']);
  assert.match(posted[0].text ?? '', /no threats detected/);
});

test('postScanSummary stays silent when signals were already posted', async () => {
  const { alerter, posted } = captureAlerter();
  await alerter.postScanSummary(12, 3, ['prod-1']);
  assert.equal(posted.length, 0);
});

test('postSignal renders the evidence rows it is given', async () => {
  const { alerter, posted } = captureAlerter();
  await alerter.postSignal(signal(), [
    { resource: '/app/keystore/wallet.json', action: 'read', process: 'node', server: 'prod-1' },
  ]);

  const rendered = JSON.stringify(posted[0].blocks);
  assert.match(rendered, /\/app\/keystore\/wallet\.json/);
  assert.match(rendered, /prod-1/);
});
