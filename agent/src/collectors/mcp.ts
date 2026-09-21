import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

export interface VigiloEvent {
  id: number;
  source: 'file_access' | 'process' | 'network' | 'auth';
  timestamp: string;
  pid?: number;
  ppid?: number;
  process?: string;
  cmd_line?: string;
  user_id?: string;
  action: string;
  resource: string;
  detail?: string;
  severity: 'info' | 'medium' | 'high' | 'critical';
  // Injected by the multi-daemon aggregator
  server?: string;
}

// Keep the old name as an alias for backwards compatibility
export type SentinelEvent = VigiloEvent;

export type MCPTransport =
  | { type: 'stdio'; command: string; args?: string[] }
  | { type: 'http'; url: string; token?: string };

type ToolContent = { type: string; text?: string };

export class VigiloMCPClient {
  private client: Client;
  readonly serverLabel: string;

  constructor(label: string) {
    this.serverLabel = label;
    this.client = new Client({ name: 'vigilo-agent', version: '0.1.0' });
  }

  async connect(transport: MCPTransport): Promise<void> {
    const t = transport.type === 'stdio'
      ? new StdioClientTransport({ command: transport.command, args: transport.args ?? [] })
      : new SSEClientTransport(
          new URL(transport.url + '/sse'),
          transport.token
            ? { requestInit: { headers: { Authorization: `Bearer ${transport.token}` } } }
            : undefined,
        );
    await this.client.connect(t);
  }

  async disconnect(): Promise<void> {
    await this.client.close();
  }

  async getFileEvents(since: Date, severity?: string): Promise<VigiloEvent[]> {
    return this.callTool('get_file_access_events', { since: since.toISOString(), severity });
  }

  async getProcessEvents(since: Date): Promise<VigiloEvent[]> {
    return this.callTool('get_process_events', { since: since.toISOString() });
  }

  async getNetworkEvents(since: Date, severity?: string): Promise<VigiloEvent[]> {
    return this.callTool('get_network_events', { since: since.toISOString(), severity });
  }

  async getAllEvents(since: Date, severity?: string, limit = 200): Promise<VigiloEvent[]> {
    return this.callTool('get_all_events', { since: since.toISOString(), severity, limit });
  }

  async getCriticalEvents(since: Date): Promise<VigiloEvent[]> {
    return this.callTool('get_critical_events', { since: since.toISOString() });
  }

  private async callTool(name: string, args: Record<string, unknown>): Promise<VigiloEvent[]> {
    const cleanArgs = Object.fromEntries(
      Object.entries(args).filter(([, v]) => v !== undefined),
    );
    const result = await this.client.callTool({ name, arguments: cleanArgs }) as { content: ToolContent[] };
    const first = result.content[0];
    const text = first?.type === 'text' ? (first.text ?? '[]') : '[]';
    try {
      const events: VigiloEvent[] = JSON.parse(text) ?? [];
      // Tag each event with the server label for cross-server correlation
      return events.map(e => ({ ...e, server: this.serverLabel }));
    } catch {
      return [];
    }
  }
}

// SentinelMCPClient kept for backwards compat
export class SentinelMCPClient extends VigiloMCPClient {
  constructor() { super('local'); }
}

/**
 * Aggregates events from multiple vigilo daemons.
 * Parse VIGILO_DAEMON_URLS as comma-separated "label=http://host:port" pairs.
 * Falls back to VIGILO_MCP_URL (single server) or stdio.
 */
export function parseTransports(): Array<{ label: string; transport: MCPTransport }> {
  const token = process.env.VIGILO_MCP_TOKEN;
  const urls = process.env.VIGILO_DAEMON_URLS;
  if (urls) {
    return urls.split(',').map(entry => {
      const [label, url] = entry.trim().split('=');
      if (!url) throw new Error(`VIGILO_DAEMON_URLS entry malformed: "${entry}" — expected label=url`);
      return { label: label.trim(), transport: { type: 'http', url: url.trim(), token } as MCPTransport };
    });
  }

  if (process.env.VIGILO_MCP_URL) {
    return [{ label: 'remote', transport: { type: 'http', url: process.env.VIGILO_MCP_URL, token } }];
  }

  return [{
    label: 'local',
    transport: {
      type: 'stdio',
      command: process.env.VIGILO_DAEMON_BIN ?? 'vigilo',
      args: ['-config', process.env.VIGILO_CONFIG ?? '/etc/vigilo/config.yaml'],
    },
  }];
}
