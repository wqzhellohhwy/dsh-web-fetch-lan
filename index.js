/**
 * @local/dsh-web-fetch-lan
 *
 * 为什么需要它：
 *   DSH 的 web_fetch 自带 SSRF 防护 —— 连接前先解析域名，只要答案里出现非公网
 *   地址就拒绝（WEB_BLOCKED_URL）。而 Clash/mihomo 的 fake-ip 模式会把所有域名
 *   解析到保留段（198.18.0.0/15、2001:2::/64），于是所有抓取都被判为
 *   "resolves to a non-public IP address"。
 *
 * 本 provider 的差别只有一处：
 *   fake-ip 段的地址视为可用（它只在 TUN 内有效，连接会被 mihomo 按其域名映射
 *   转发，到达的正是你本来要访问的站点）；其余私网/保留地址仍然一律拒绝
 *   （127/8、10/8、192.168/16、169.254/16、100.64/10、::1、fc00::/7 等），
 *   所以指向本机 GUI、内网设备、云元数据端点的 URL 依然被挡住。
 *   fake-ip 段可在 loader 行的 config 里改（fakeIpRanges / fakeIpRanges6），
 *   默认 198.18.0.0/15 与 2001:2::/64 + fdfe:dcba:9876::/64；配置非法时回退默认。
 *
 * 额外修正：
 *   实测在本机 Clash TUN + fake-ip 环境下，若让 Node 按 DNS 原顺序（verbatim，
 *   即 IPv6 优先）连接，HTTPS 会间歇性 ECONNRESET；改成 IPv4 优先后连续 8/8 成功
 *   （fake-ip 的 v4/v6 地址本身 TCP 都是通的，问题出在 v6 路径的 TLS 阶段）。
 *   因此 apply() 会把本进程的 DNS 结果顺序设为 ipv4first —— 这只是排序偏好，
 *   IPv6 仍然可用，只有在没有 A 记录时才会走 AAAA。
 *
 * 依赖：无（只用 Node 内置模块和全局 fetch）。
 */

import dns from 'node:dns/promises';
import { setDefaultResultOrder } from 'node:dns';
import { isIP } from 'node:net';

export const name = 'web-fetch-lan';
export const inject = ['web'];

const PROVIDER_ID = 'http-lan';
const USER_AGENT = 'DeepSeekHarness-web-fetch-lan/1.0';
const ACCEPT = 'text/html,application/xhtml+xml,text/*;q=0.9,application/json;q=0.8';
const MAX_REDIRECTS = 5;
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_CHARS = 200000;
const TIMEOUT_MS = 30000;
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

/**
 * fake-ip 段：放行（Clash/mihomo 默认 198.18.0.0/15 与 2001:2::/64）。
 * 可在 loader 行的 config 里覆盖（见 cordis.patch.yml 与 resolveConfig）。
 */
const DEFAULT_FAKEIP_V4 = ['198.18.0.0/15'];
const DEFAULT_FAKEIP_V6 = ['2001:2::/64', 'fdfe:dcba:9876::/64'];
const DEFAULT_RANGES = { v4: DEFAULT_FAKEIP_V4, v6: DEFAULT_FAKEIP_V6 };

/** 其余明确禁止的段（不在此列表里的地址按公网处理）。 */
const BLOCK_V4 = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.88.99.0/24',
  '192.168.0.0/16',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
];
const BLOCK_V6 = [
  '::/128',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8',
  '64:ff9b::/96',
  '64:ff9b:1::/48',
  '2001::/32',
  '2001:db8::/32',
];

/* ------------------------------- 地址工具 ------------------------------- */

function parseV4(text) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(text).trim());
  if (!m) return null;
  const octets = m.slice(1).map((x) => Number(x));
  return octets.some((n) => n > 255 || !Number.isInteger(n)) ? null : octets;
}

function inCidr4(octets, cidr) {
  const [addr, bitsText] = String(cidr).split('/');
  const net = parseV4(addr);
  if (!net) return false;
  const bits = Number(bitsText);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const value = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const base = ((net[0] << 24) | (net[1] << 16) | (net[2] << 8) | net[3]) >>> 0;
  return ((value & mask) >>> 0) === ((base & mask) >>> 0);
}

/** 把 IPv6 文本展开为 8 个 16 位分组；无可解析返回 null。 */
function v6Groups(input) {
  let text = String(input).trim().toLowerCase();
  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone);

  const lastColon = text.lastIndexOf(':');
  if (lastColon !== -1) {
    const tail = text.slice(lastColon + 1);
    if (tail.includes('.')) {
      const v4 = parseV4(tail);
      if (!v4) return null;
      const hi = ((v4[0] << 8) | v4[1]).toString(16);
      const lo = ((v4[2] << 8) | v4[3]).toString(16);
      text = text.slice(0, lastColon + 1) + hi + ':' + lo;
    }
  }

  const halves = text.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':').filter((x) => x !== '') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter((x) => x !== '') : [];
  const gap = 8 - left.length - right.length;
  if (halves.length === 2) {
    if (gap < 0) return null;
  } else if (gap !== 0) {
    return null;
  }
  const groups = halves.length === 2 ? [...left, ...new Array(gap).fill('0'), ...right] : [...left];
  if (groups.length !== 8) return null;
  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

function inCidr6(groups, cidr) {
  const [addr, bitsText] = String(cidr).split('/');
  const net = v6Groups(addr);
  if (!net) return false;
  let remaining = Number(bitsText);
  for (let i = 0; i < 8 && remaining > 0; i++) {
    const take = Math.min(16, remaining);
    const mask = take === 16 ? 0xffff : (0xffff << (16 - take)) & 0xffff;
    if ((groups[i] & mask) !== (net[i] & mask)) return false;
    remaining -= take;
  }
  return true;
}

const matches4 = (octets, list) => list.some((cidr) => inCidr4(octets, cidr));

function isValidCidr4(cidr) {
  const [addr, bitsText, extra] = String(cidr).split('/');
  if (extra !== undefined || !parseV4(addr)) return false;
  const bits = Number(bitsText);
  return Number.isInteger(bits) && bits >= 0 && bits <= 32;
}

function isValidCidr6(cidr) {
  const [addr, bitsText, extra] = String(cidr).split('/');
  if (extra !== undefined || !v6Groups(addr)) return false;
  const bits = Number(bitsText);
  return Number.isInteger(bits) && bits >= 0 && bits <= 128;
}

/**
 * 把 loader 行的 config 归一成 { fakeIpRanges, fakeIpRanges6 }。
 * 缺省 / 非数组 / 全部非法时回退到内置默认段，绝不让配置错误变成"静默放行"。
 */
export function resolveConfig(config) {
  const raw = config !== null && typeof config === 'object' && !Array.isArray(config) ? config : {};

  const pick = (value, defaults, isValid, label) => {
    if (value === undefined || value === null) return defaults.slice();
    if (!Array.isArray(value)) {
      console.warn(`[web-fetch-lan] config.${label} 不是数组，已忽略并沿用默认段`);
      return defaults.slice();
    }
    const kept = value
      .filter((item) => typeof item === 'string' && isValid(item.trim()))
      .map((item) => item.trim());
    const dropped = value.length - kept.length;
    if (dropped > 0) console.warn(`[web-fetch-lan] config.${label} 忽略了 ${dropped} 条非法 CIDR`);
    if (kept.length === 0) {
      if (value.length > 0) console.warn(`[web-fetch-lan] config.${label} 无有效条目，回退默认段`);
      return defaults.slice();
    }
    return kept;
  };

  return {
    fakeIpRanges: pick(raw.fakeIpRanges, DEFAULT_FAKEIP_V4, isValidCidr4, 'fakeIpRanges'),
    fakeIpRanges6: pick(raw.fakeIpRanges6, DEFAULT_FAKEIP_V6, isValidCidr6, 'fakeIpRanges6'),
  };
}

/** 'fakeip' | 'blocked' | 'invalid' | 'public' */
function classify(address, ranges = DEFAULT_RANGES) {
  const fakeV4 = ranges?.v4 ?? DEFAULT_FAKEIP_V4;
  const fakeV6 = ranges?.v6 ?? DEFAULT_FAKEIP_V6;
  const family = isIP(address);
  if (family === 4) {
    const octets = parseV4(address);
    if (!octets) return 'invalid';
    if (matches4(octets, fakeV4)) return 'fakeip';
    if (matches4(octets, BLOCK_V4)) return 'blocked';
    return 'public';
  }
  if (family === 6) {
    const groups = v6Groups(address);
    if (!groups) return 'invalid';
    if (fakeV6.some((cidr) => inCidr6(groups, cidr))) return 'fakeip';
    const mapped = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff;
    if (mapped) {
      const octets = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff];
      if (matches4(octets, fakeV4)) return 'fakeip';
      if (matches4(octets, BLOCK_V4)) return 'blocked';
      return 'public';
    }
    if (BLOCK_V6.some((cidr) => inCidr6(groups, cidr))) return 'blocked';
    return 'public';
  }
  return 'invalid';
}

/* ------------------------------- 抓取实现 ------------------------------- */

function validateUrl(input) {
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error(`invalid URL "${input}"`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`unsupported URL scheme "${url.protocol}"`);
  }
  if (url.username !== '' || url.password !== '') {
    throw new Error('credentials in URLs are not allowed');
  }
  return url;
}

async function assertReachable(url, ranges) {
  const host = url.hostname.replace(/^\[/, '').replace(/\]$/, '');
  if (isIP(host) !== 0) {
    const kind = classify(host, ranges);
    if (kind === 'public' || kind === 'fakeip') return;
    throw new Error(`URL host "${host}" is not a public address`);
  }
  let answers;
  try {
    answers = await dns.lookup(host, { all: true, order: 'verbatim' });
  } catch (error) {
    throw new Error(`hostname "${host}" could not be resolved (${error.code ?? error.message})`);
  }
  if (answers.length === 0) throw new Error(`hostname "${host}" resolved to no addresses`);
  for (const answer of answers) {
    const kind = classify(answer.address, ranges);
    if (kind === 'public' || kind === 'fakeip') continue;
    throw new Error(`URL hostname "${host}" resolves to a non-public IP address (${answer.address})`);
  }
}

function classifyContentType(contentType) {
  const type = String(contentType).split(';')[0].trim().toLowerCase();
  if (type === 'text/html' || type === 'application/xhtml+xml') return 'html';
  if (type.startsWith('text/')) return 'text';
  if (type === 'application/json' || type.endsWith('+json')) return 'text';
  if (type === 'application/xml' || type.endsWith('+xml')) return 'text';
  return undefined;
}

function decoderFor(contentType) {
  const match = /charset\s*=\s*"?([^";\s]+)"?/i.exec(String(contentType));
  const label = match ? match[1].toLowerCase() : 'utf-8';
  if (label === 'utf-8' || label === 'utf8') return new TextDecoder('utf-8');
  try {
    return new TextDecoder(label);
  } catch {
    return new TextDecoder('utf-8');
  }
}

async function readCapped(response) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_BYTES) {
    await response.body?.cancel();
    throw new Error(`response exceeds the maximum of ${MAX_BYTES} bytes`);
  }
  if (response.body === null) return { bytes: new Uint8Array(0), truncated: false };
  const chunks = [];
  let total = 0;
  let truncated = false;
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = MAX_BYTES - total;
      if (value.byteLength > remaining) {
        chunks.push(value.subarray(0, remaining));
        total += remaining;
        truncated = true;
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { bytes, truncated };
}

async function readBody(response, finalUrl) {
  const contentType = response.headers.get('content-type') ?? '';
  const kind = classifyContentType(contentType);
  if (kind === undefined) {
    await response.body?.cancel();
    throw new Error(`unsupported content type "${contentType || 'unknown'}"`);
  }
  const { bytes, truncated } = await readCapped(response);
  const text = decoderFor(contentType).decode(bytes);
  const clipped = text.length > MAX_CHARS;
  return {
    url: finalUrl.toString(),
    statusCode: response.status,
    body: { kind, content: clipped ? text.slice(0, MAX_CHARS) : text },
    truncated: truncated || clipped,
  };
}

class LanFetchProvider {
  id = PROVIDER_ID;

  /** @param {{v4: string[], v6: string[]}} ranges fake-ip 段（来自 loader config）。 */
  constructor(ranges = DEFAULT_RANGES) {
    this.ranges = ranges;
  }

  available() {
    return true;
  }

  async fetch(request, signal) {
    const timeout = AbortSignal.timeout(TIMEOUT_MS);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    const initial = validateUrl(request.url);
    let current = initial;
    let redirects = 0;

    for (;;) {
      await assertReachable(current, this.ranges);
      const response = await fetch(current, {
        redirect: 'manual',
        signal: combined,
        headers: { 'user-agent': USER_AGENT, accept: ACCEPT },
      });

      if (!REDIRECT_STATUS.has(response.status)) return await readBody(response, current);

      if (redirects >= MAX_REDIRECTS) {
        await response.body?.cancel();
        throw new Error(`exceeded the maximum of ${MAX_REDIRECTS} redirects`);
      }
      const location = response.headers.get('location');
      if (location === null) {
        await response.body?.cancel();
        throw new Error(`redirect response (HTTP ${response.status}) without a Location header`);
      }
      let next;
      try {
        next = new URL(location, current);
      } catch {
        await response.body?.cancel();
        throw new Error(`invalid redirect Location "${location}"`);
      }
      if (next.origin !== current.origin) {
        await response.body?.cancel();
        throw new Error(`cross-origin redirect to ${next.origin} is not followed automatically; retry against that URL directly`);
      }
      await response.body?.cancel();
      current = next;
      redirects += 1;
    }
  }
}

export function apply(ctx, config = {}) {
  const { fakeIpRanges, fakeIpRanges6 } = resolveConfig(config);
  // 让 undici 优先使用 A 记录，绕开 fake-ip IPv6 路径上的 ECONNRESET。
  try {
    setDefaultResultOrder('ipv4first');
  } catch {
    /* 旧运行时没有这个 API 时保持默认顺序 */
  }
  const note = `[web-fetch-lan] fake-ip 段 v4=${fakeIpRanges.join(',')} v6=${fakeIpRanges6.join(',') || '(无)'}`;
  if (typeof ctx?.logger?.info === 'function') ctx.logger.info(note);
  else console.log(note);
  ctx.web.registerFetchProvider(new LanFetchProvider({ v4: fakeIpRanges, v6: fakeIpRanges6 }));
}

export { LanFetchProvider, classify };
