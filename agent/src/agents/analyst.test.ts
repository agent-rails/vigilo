import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeEvents, findLastJsonArray, AnalysisParseError, ModelCall } from './analyst';
import { VigiloEvent } from '../collectors/mcp';

function event(over: Partial<VigiloEvent> & { id: number }): VigiloEvent {
  return {
    source: 'file_access',
    timestamp: '2026-09-23T00:00:00Z',
    action: 'read',
    resource: `/var/log/noise-${over.id}.log`,
    severity: 'info',
    server: 'prod-1',
    ...over,
  };
}

// A response shaped like the real one: a <dup_check> preamble, then the JSON
// array, with the attacker-chosen filename quoted back in the prose and in the
// signal body — which is exactly what the system prompt asks the model to do.
function modelResponse(filename: string, evidenceIndices: unknown = [0]): string {
  return `<dup_check>\n1. Keystore read of ${filename} — distinct from others because: only signal\n</dup_check>\n` +
    JSON.stringify([{
      severity: 'critical',
      category: 'key_exfiltration',
      title: `Unexpected read of ${filename}`,
      description: `node read ${filename}, which holds wallet material.`,
      suggestedAction: 'Rotate the wallet key',
      evidenceIndices,
      server: 'prod-1',
    }], null, 2);
}

const replies = (...out: string[]): { call: ModelCall; calls: () => number } => {
  let i = 0;
  return {
    call: async () => out[Math.min(i++, out.length - 1)],
    calls: () => i,
  };
};

// ── #32: a filename must not be able to silence the analyst ──────────────────

for (const filename of ['wallet.json', 'wallet].json', 'wallet[.json', 'w]a[l]let.json']) {
  test(`findLastJsonArray survives an unbalanced bracket in "${filename}"`, () => {
    const parsed = findLastJsonArray(modelResponse(filename));
    assert.ok(parsed, `expected a parsed array for ${filename}`);
    assert.equal(parsed.length, 1);
    assert.equal((parsed[0] as { title: string }).title, `Unexpected read of ${filename}`);
  });
}

test('findLastJsonArray ignores brackets inside escaped string literals', () => {
  const raw = '<dup_check>none</dup_check>\n' +
    JSON.stringify([{ title: 'read of "wallet].json\\" [orphan" quoted oddly', evidenceIndices: [] }]);
  const parsed = findLastJsonArray(raw);
  assert.ok(parsed);
  assert.equal(parsed.length, 1);
});

test('findLastJsonArray returns the last complete array, not a nested one', () => {
  const raw = 'prose [1, 2] more prose\n[{"title":"a","evidenceIndices":[0,3,7]}]';
  const parsed = findLastJsonArray(raw);
  assert.deepEqual(parsed, [{ title: 'a', evidenceIndices: [0, 3, 7] }]);
});

test('findLastJsonArray parses a bare array with no preamble', () => {
  assert.deepEqual(findLastJsonArray('  []  '), []);
});

test('findLastJsonArray returns null when there is no array at all', () => {
  assert.equal(findLastJsonArray('<dup_check>none</dup_check> I could not comply.'), null);
});

test('findLastJsonArray stays bounded against a bracket flood', () => {
  const raw = '['.repeat(50_000) + '\n[{"title":"a"}]';
  const started = Date.now();
  const parsed = findLastJsonArray(raw);
  assert.ok(Date.now() - started < 2_000, 'bracket flood must not blow up the scan');
  assert.equal(parsed, null); // budget exhausted; reported as a failure, never as a clean scan
});

test('analyzeEvents returns the signal when the response quotes an unbalanced filename', async () => {
  const { call, calls } = replies(modelResponse('wallet].json'));
  const signals = await analyzeEvents([event({ id: 1, severity: 'critical' })], ['prod-1'], call);
  assert.equal(signals.length, 1);
  assert.equal(signals[0].title, 'Unexpected read of wallet].json');
  assert.equal(calls(), 1, 'no corrective re-ask should have been needed');
});

test('analyzeEvents throws rather than reporting zero signals when parsing fails', async () => {
  const broken = '<dup_check>none</dup_check>\n[{"title": "x",}]';
  const { call, calls } = replies(broken, broken);
  await assert.rejects(
    () => analyzeEvents([event({ id: 1, severity: 'critical' })], ['prod-1'], call),
    (err: unknown) => err instanceof AnalysisParseError,
  );
  assert.equal(calls(), 2, 'the inspector re-ask should still fire once before giving up');
});

test('analyzeEvents still returns an empty list for a genuine no-threat response', async () => {
  const { call } = replies('<dup_check>none</dup_check>\n[]');
  const signals = await analyzeEvents([event({ id: 1, severity: 'critical' })], ['prod-1'], call);
  assert.deepEqual(signals, []);
});

test('compacted model evidence indices still address the original event list', async () => {
  const events = Array.from({ length: 200 }, (_, id) => event({ id, severity: 'info' }));
  events[199].severity = 'critical'; // compaction moves this event to the front
  let prompt = '';
  const call: ModelCall = async (messages) => {
    prompt = String(messages[0].content);
    return modelResponse('wallet.json', [199]);
  };

  const signals = await analyzeEvents(events, ['prod-1'], call);
  assert.equal(signals[0].evidenceIndices[0], 199);
  assert.match(prompt, /"index": 199,[\s\S]*?"resource": "\/var\/log\/noise-199\.log"[\s\S]*?"id": 199/);
  assert.doesNotMatch(prompt, /"index": 0,[\s\S]*?"resource": "\/var\/log\/noise-199\.log"/);
});
