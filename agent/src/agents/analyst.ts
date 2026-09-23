import Anthropic, { APIError } from '@anthropic-ai/sdk';
import { createHash } from 'crypto';
import { VigiloEvent } from '../collectors/mcp';

// Constructed on first use: importing the module must not require credentials.
let client: Anthropic | undefined;
const anthropic = (): Anthropic => (client ??= new Anthropic());

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Signal {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  suggestedAction: string;
  evidenceIndices: number[];
  detectedAt: Date;
  server?: string;
}

/**
 * The analyst produced a response its own output contract could not read.
 * Distinct from "analysed successfully, found nothing" — callers must not
 * render this as a clean scan.
 */
export class AnalysisParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AnalysisParseError';
  }
}

const SYSTEM = `You are a principal security analyst specializing in crypto infrastructure threat detection.

Analyze OS-level events from servers running crypto infrastructure (hot wallets, signing services, bridge validators, exchange integrations).

Events may come from multiple servers — each has a "server" field. Cross-server patterns (e.g. lateral movement, coordinated exfiltration) are especially significant.

Look for attack patterns including:
- Private key / keystore file read by unexpected process → exfiltration likely
- Shell (bash/sh) spawned from app process (node, python) → RCE / code injection
- Outbound connection to suspicious port or new IP after file access → active exfiltration
- Environment variable dump followed by outbound connection → secret theft
- New process reading .env or credential files → credential harvesting
- Unexpected package install (npm/pip) → supply chain / persistence
- Privilege escalation (sudo by app process) → attacker expanding access
- Crypto-specific: access to keystore/, wallet.json, mnemonic files, .pem keys
- Cross-server: same attack pattern on multiple servers → coordinated campaign

For each threat sequence, output one signal. Correlate across sources and servers.

BEFORE the JSON, you MUST emit a <dup_check> block. In it, list each signal you plan to emit and confirm it is semantically distinct from the others. Same root cause expressed differently (e.g. two processes reading the same key file) counts as ONE signal — collapse them. Remove duplicates before the JSON.

<dup_check>
1. [title] — distinct from others because: [reason]
2. [title] — distinct from others because: [reason]
</dup_check>

Then respond with a valid JSON array of signals. No markdown, no explanation outside the dup_check block and the JSON:
[{
  "severity": "low|medium|high|critical",
  "category": "key_exfiltration|rce|credential_theft|supply_chain|privilege_escalation|lateral_movement|reconnaissance",
  "title": "one-line summary",
  "description": "2-3 sentences explaining the threat and why it is suspicious",
  "suggestedAction": "immediate mitigation step",
  "evidenceIndices": [0, 3, 7],
  "server": "server label or null if cross-server"
}]

If no threats detected, emit <dup_check>none</dup_check> then [].`;

/**
 * Stable dedup hash for a signal — based on category + title fingerprint.
 * Does not include time so the same attack re-hashes identically across scans.
 */
export function signalDedupHash(category: string, title: string, server?: string): string {
  return createHash('sha256')
    .update([category, title.toLowerCase().replace(/\s+/g, ' '), server ?? ''].join('|'))
    .digest('hex')
    .slice(0, 32);
}

// ── Goose pattern: Context compaction ────────────────────────────────────────
const MAX_EVENTS = 150;
const SAMPLE_LOW_PRIORITY_EVERY = 3;

function compactEvents(events: VigiloEvent[]): { compacted: { event: VigiloEvent; index: number }[]; note: string } {
  if (events.length <= MAX_EVENTS) {
    return { compacted: events.map((event, index) => ({ event, index })), note: '' };
  }

  const indexed = events.map((event, index) => ({ event, index }));
  const high    = indexed.filter(({ event }) => event.severity === 'critical' || event.severity === 'high');
  const low     = indexed.filter(({ event }) => event.severity === 'medium'   || event.severity === 'info');
  const sampled = low.filter((_, i) => i % SAMPLE_LOW_PRIORITY_EVERY === 0);
  const compacted = [...high, ...sampled].slice(0, MAX_EVENTS);

  const note =
    `[Context compacted: ${events.length} total events → ${compacted.length} shown. ` +
    `All ${high.length} critical/high events included; medium/info sampled 1-in-${SAMPLE_LOW_PRIORITY_EVERY}.]`;

  return { compacted, note };
}

// ── Goose pattern: MOIM preamble ─────────────────────────────────────────────
function buildMoim(events: VigiloEvent[], servers: string[]): string {
  const serverList = servers.length > 0 ? servers.join(', ') : 'local';
  const bySeverity = {
    critical: events.filter(e => e.severity === 'critical').length,
    high:     events.filter(e => e.severity === 'high').length,
    medium:   events.filter(e => e.severity === 'medium').length,
    info:     events.filter(e => e.severity === 'info').length,
  };
  return [
    `[Monitoring scope: ${servers.length || 1} server(s): ${serverList}]`,
    `[Event breakdown: ${bySeverity.critical} critical, ${bySeverity.high} high, ${bySeverity.medium} medium, ${bySeverity.info} info]`,
    `[Scan time: ${new Date().toISOString()}]`,
  ].join('  ');
}

// ── Response extraction helpers ───────────────────────────────────────────────
//
// Agents emit structured content mid-response with prose on either side, and
// that prose can quote attacker-chosen strings. Extraction must therefore be
// driven by a real parser, never by counting delimiters.

// Bounds the work spent on bracket runs that never close. Response bodies are
// capped at max_tokens, but the bracket density inside them is attacker-chosen
// (a filename may contain any byte but '/' and NUL), so the scan is not allowed
// to be quadratic in that count.
const MAX_ARRAY_CANDIDATES = 64;

function parseArray(text: string): unknown[] | null {
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

// Index of the ']' closing the '[' at `start`, or -1. Tracks quote state and
// backslash escapes, so a bracket inside a string literal cannot change depth.
function matchArrayEnd(text: string, start: number): number {
  let depth = 0, inString = false, escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if      (escaped)     escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"')  inString = false;
      continue;
    }
    if      (ch === '"') inString = true;
    else if (ch === '[') depth++;
    else if (ch === ']' && --depth === 0) return i;
  }
  return -1;
}

// Finds the last complete [...] array in text.
//
// Agents often emit structured content mid-response with trailing prose, so the
// last *complete* array is the one we want — a greedy /\[[\s\S]*\]/ matches the
// first '[' to the last ']' and returns a malformed superset.
//
// Each candidate is validated by JSON.parse rather than by bracket counting:
// an unbalanced bracket in prose is skipped, and one inside a quoted value is
// invisible to the depth counter. Nested arrays are stepped over, so an
// evidenceIndices list is never mistaken for the signal array.
export function findLastJsonArray(text: string): unknown[] | null {
  const whole = parseArray(text.trim());
  if (whole) return whole;

  let found: unknown[] | null = null;
  let attempts = 0;
  let i = text.indexOf('[');

  while (i !== -1 && attempts < MAX_ARRAY_CANDIDATES) {
    const end = matchArrayEnd(text, i);
    const parsed = end === -1 ? null : parseArray(text.slice(i, end + 1));
    if (parsed) {
      found = parsed;
      i = text.indexOf('[', end + 1);
    } else {
      attempts++;
      i = text.indexOf('[', i + 1);
    }
  }

  return found;
}

// Finds the last <tag>…</tag> block via backward scan.
function findTaggedContent(text: string, tag: string): string | null {
  const close = `</${tag}>`, open = `<${tag}>`;
  const ci = text.lastIndexOf(close);
  if (ci === -1) return null;
  const oi = text.lastIndexOf(open, ci);
  if (oi === -1) return null;
  return text.slice(oi + open.length, ci);
}

type RawSignal = Omit<Signal, 'id' | 'detectedAt'>;

function parseSignals(raw: string): RawSignal[] | null {
  return findLastJsonArray(raw) as RawSignal[] | null;
}

// ── Exponential backoff on transient API errors ───────────────────────────────
//
// The reference harness resumes Claude Code CLI sessions on 429/5xx.
// For the Messages API, session state lives in the messages[] array —
// we rebuild it on each retry, which is equivalent.

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 529]);
const MAX_ATTEMPTS = 6;
const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

export type ModelCall = (messages: Anthropic.MessageParam[]) => Promise<string>;

async function callClaude(messages: Anthropic.MessageParam[]): Promise<string> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    if (attempt > 0) await sleep(Math.min(2 ** attempt * 1_000, 30_000));
    try {
      const msg = await anthropic().messages.create({
        model: 'claude-opus-4-7',
        max_tokens: 4096,
        system: SYSTEM,
        messages,
      });
      return msg.content[0].type === 'text' ? msg.content[0].text : '[]';
    } catch (err) {
      const status = (err as APIError)?.status;
      if (status != null && RETRYABLE_STATUS.has(status)) { lastErr = err; continue; }
      throw err;
    }
  }
  throw lastErr;
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function analyzeEvents(
  events: VigiloEvent[],
  servers: string[] = [],
  call: ModelCall = callClaude,
): Promise<Signal[]> {
  if (events.length === 0) return [];

  const { compacted, note } = compactEvents(events);
  const moim = buildMoim(compacted.map(({ event }) => event), servers);
  // Preserve the original event index: the caller resolves evidence against
  // the full event list, while compaction reorders and drops entries.
  const indexed = compacted.map(({ event, index }) => ({ index, ...event }));

  const userContent = [
    moim,
    note,
    `\nAnalyze these ${compacted.length} OS-level events for attack patterns:\n\n${JSON.stringify(indexed, null, 2)}`,
  ].filter(Boolean).join('\n');

  const baseMessages: Anthropic.MessageParam[] = [
    { role: 'user', content: userContent },
  ];

  let raw = await call(baseMessages);

  // ── Forced dedup reasoning gate ───────────────────────────────────────────
  // If <dup_check> is absent, Claude skipped its dedup reasoning pass.
  // Correct with a single follow-up turn (conversation context preserved).
  if (!findTaggedContent(raw, 'dup_check')) {
    raw = await call([
      ...baseMessages,
      { role: 'assistant', content: raw },
      {
        role: 'user',
        content: 'You must emit a <dup_check>…</dup_check> block before the JSON array. ' +
          'Re-emit your full response with the dedup reasoning included.',
      },
    ]);
  }

  let parsed = parseSignals(raw);

  // ── Inspector: single retry on malformed JSON ─────────────────────────────
  if (parsed === null) {
    raw = await call([
      ...baseMessages,
      { role: 'assistant', content: raw },
      {
        role: 'user',
        content: '[Previous response did not contain a valid JSON array. ' +
          'Respond with <dup_check>…</dup_check> then ONLY the JSON array — no other prose.]',
      },
    ]);
    parsed = parseSignals(raw);
  }

  // A response we could not read is not a clean scan. Raising here keeps that
  // fact from collapsing into an empty signal list, which callers render as
  // "analysed, nothing found".
  if (!parsed) {
    throw new AnalysisParseError('analyst response contained no parseable JSON array (retried once)');
  }

  return parsed.map(s => ({
    ...s,
    id: createHash('sha256')
      .update(`${s.category}:${s.title}:${Date.now()}`)
      .digest('hex')
      .slice(0, 16),
    detectedAt: new Date(),
  }));
}
