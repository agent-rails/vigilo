import { WebClient, type Block, type KnownBlock } from '@slack/web-api';
import { Signal, Severity } from '../agents/analyst';

const EMOJI: Record<Severity, string> = {
  low: ':information_source:',
  medium: ':warning:',
  high: ':rotating_light:',
  critical: ':skull_and_crossbones:',
};

export class SlackAlerter {
  private client: WebClient;
  constructor(token: string, private channel: string) {
    this.client = new WebClient(token);
  }

  async postSignal(signal: Signal, events: { resource: string; action: string; process?: string; server?: string }[]): Promise<string> {
    const emoji = EMOJI[signal.severity];
    const evidence = events
      .slice(0, 3)
      .map(e => `• \`${e.action}\` → \`${e.resource}\`${e.process ? ` (${e.process})` : ''}${e.server ? ` [${e.server}]` : ''}`)
      .join('\n');

    const blocks: KnownBlock[] = [
      {
        type: 'header',
        text: { type: 'plain_text', text: `${emoji} ${signal.title}`, emoji: true },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn' as const, text: `*Severity*\n${signal.severity.toUpperCase()}` },
          { type: 'mrkdwn' as const, text: `*Category*\n${signal.category.replace(/_/g, ' ')}` },
          { type: 'mrkdwn' as const, text: `*Detected*\n<!date^${Math.floor(signal.detectedAt.getTime() / 1000)}^{time_secs}|${signal.detectedAt.toISOString()}>` },
          { type: 'mrkdwn' as const, text: `*Signal ID*\n\`${signal.id}\`` },
        ],
      },
      { type: 'section', text: { type: 'mrkdwn' as const, text: `*What happened*\n${signal.description}` } },
      ...(evidence ? [{ type: 'section' as const, text: { type: 'mrkdwn' as const, text: `*Evidence*\n${evidence}` } }] : []),
      { type: 'section', text: { type: 'mrkdwn' as const, text: `*Action needed*\n${signal.suggestedAction}` } },
    ];

    const res = await this.client.chat.postMessage({
      channel: this.channel,
      text: `${emoji} ${signal.title}`,
      blocks,
    });

    return res.ts as string;
  }

  async postScanSummary(eventsAnalyzed: number, signalCount: number, servers: string[] = []): Promise<void> {
    if (signalCount > 0) return; // individual alerts already posted
    const serverNote = servers.length > 1 ? ` across ${servers.length} servers` : '';
    await this.client.chat.postMessage({
      channel: this.channel,
      text: `:white_check_mark: Vigilo scan${serverNote} — ${eventsAnalyzed} events, no threats detected`,
    });
  }

  /**
   * Reports a scan that did not complete. Never phrased as a result: the events
   * were collected but not analysed, so the window is unassessed, not clean.
   */
  async postScanFailure(eventsAnalyzed: number, reason: string, servers: string[] = []): Promise<void> {
    const serverNote = servers.length > 1 ? ` across ${servers.length} servers` : '';
    await this.client.chat.postMessage({
      channel: this.channel,
      text: `:rotating_light: Vigilo scan${serverNote} INCOMPLETE — ${eventsAnalyzed} events collected; results may be partial (${reason}). ` +
        `This window is unassessed; treat it as unchecked, not clear.`,
    });
  }
}
