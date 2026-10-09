/**
 * @local/dsh-web-fetch-lan 自检（零依赖，node selftest.mjs）。
 *
 * 覆盖三件事：
 *   1. resolveConfig 对 loader config 的归一与回退（缺省 / 自定义 / 非法）；
 *   2. classify 在默认段与自定义段下的判定；
 *   3. apply() 装配出的 provider：内网仍被拒、自定义 fake-ip 段被放行。
 * 末尾附带一次真实网络抓取，失败只提示（可能只是代理没开），不计入退出码。
 */

import { apply, classify, resolveConfig, LanFetchProvider } from './index.js';

let failed = 0;
function check(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failed += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  => ${JSON.stringify(actual)}${ok ? '' : ` (期望 ${JSON.stringify(expected)})`}`);
}

/* 1. resolveConfig -------------------------------------------------------- */

const DEFAULTS = { fakeIpRanges: ['198.18.0.0/15'], fakeIpRanges6: ['2001:2::/64', 'fdfe:dcba:9876::/64'] };
check('无 config 时用默认段', resolveConfig(undefined), DEFAULTS);
check('config 为 null 时用默认段', resolveConfig(null), DEFAULTS);
check('config 为数组时用默认段', resolveConfig([1, 2]), DEFAULTS);
check('空对象时用默认段', resolveConfig({}), DEFAULTS);
check('自定义 v4 段生效', resolveConfig({ fakeIpRanges: ['10.0.0.0/8'] }).fakeIpRanges, ['10.0.0.0/8']);
check(
  '自定义 v6 段生效',
  resolveConfig({ fakeIpRanges6: ['2001:2::/64'] }).fakeIpRanges6,
  ['2001:2::/64'],
);
check(
  '非法 CIDR 被剔除、其余保留',
  resolveConfig({ fakeIpRanges: ['198.18.0.0/15', 'not-a-cidr', '10.0.0.0/33', '300.1.1.1/8', ''] }).fakeIpRanges,
  ['198.18.0.0/15'],
);
check('全是非法条目时回退默认', resolveConfig({ fakeIpRanges: ['nope'] }).fakeIpRanges, DEFAULTS.fakeIpRanges);
check('非数组时回退默认', resolveConfig({ fakeIpRanges: '198.18.0.0/15' }).fakeIpRanges, DEFAULTS.fakeIpRanges);
check('只覆盖一个字段，另一个保持默认', resolveConfig({ fakeIpRanges: ['10.0.0.0/8'] }).fakeIpRanges6, DEFAULTS.fakeIpRanges6);
check(
  '带空白的条目被 trim',
  resolveConfig({ fakeIpRanges: ['  198.18.0.0/15  '] }).fakeIpRanges,
  ['198.18.0.0/15'],
);

/* 2. classify ------------------------------------------------------------- */

const D = { v4: DEFAULTS.fakeIpRanges, v6: DEFAULTS.fakeIpRanges6 };
check('默认段内 v4 => fakeip', classify('198.18.0.17', D), 'fakeip');
check('默认段内 v6 => fakeip', classify('2001:2::11', D), 'fakeip');
check('公网 v4 => public', classify('104.20.23.154', D), 'public');
check('公网 v6 => public', classify('2606:4700::1111', D), 'public');
check('回环 => blocked', classify('127.0.0.1', D), 'blocked');
check('云元数据 => blocked', classify('169.254.169.254', D), 'blocked');
check('私网 => blocked', classify('192.168.3.1', D), 'blocked');
check('CGNAT => blocked', classify('100.64.0.1', D), 'blocked');
check('IPv6 回环 => blocked', classify('::1', D), 'blocked');
check('ULA => blocked', classify('fd00::1', D), 'blocked');
check('v4-mapped 默认段 => fakeip', classify('::ffff:198.18.0.17', D), 'fakeip');
check('v4-mapped 私网 => blocked', classify('::ffff:192.168.3.1', D), 'blocked');
check('垃圾输入 => invalid', classify('not-an-ip', D), 'invalid');

const CUSTOM = { v4: ['192.168.0.0/16'], v6: [] };
check('自定义段内的私网地址 => fakeip', classify('192.168.3.1', CUSTOM), 'fakeip');
check('自定义段外的私网地址 => blocked', classify('10.1.2.3', CUSTOM), 'blocked');

/* 3. apply 装配出来的 provider -------------------------------------------- */

const registered = [];
const fakeCtx = { web: { registerFetchProvider: (provider) => registered.push(provider) } };
apply(fakeCtx, { fakeIpRanges: ['10.0.0.0/8'], fakeIpRanges6: [] });
check('注册了恰好一个 provider', registered.length, 1);
check('provider id', registered[0].id, 'http-lan');
check('provider 可用', registered[0].available(), true);
check('provider 是 LanFetchProvider', registered[0] instanceof LanFetchProvider, true);

async function expectReject(provider, url, needle) {
  try {
    await provider.fetch({ url });
    check(`拒绝 ${url}`, '没有抛错', `包含 "${needle}" 的错误`);
  } catch (error) {
    check(`拒绝 ${url}`, String(error.message).includes(needle), true);
  }
}

const custom = new LanFetchProvider({ v4: ['10.0.0.0/8'], v6: [] });
await expectReject(custom, 'http://127.0.0.1:19387/', 'not a public address');
await expectReject(custom, 'http://169.254.169.254/', 'not a public address');
await expectReject(custom, 'http://[::1]:19387/', 'not a public address');
await expectReject(custom, 'http://192.168.3.1/', 'not a public address');
await expectReject(custom, 'file:///C:/Windows/win.ini', 'unsupported URL scheme');
await expectReject(custom, 'http://user:pw@example.com/', 'credentials in URLs are not allowed');

// 自定义 fake-ip 段内的地址会通过 SSRF 校验，随后才因连不上而失败 ——
// 只要错误不是 "not a public address"，就说明放行逻辑按 config 生效了。
try {
  await custom.fetch({ url: 'http://10.255.255.1/' });
  check('自定义段内 10.255.255.1 放行', '意外成功', '网络错误或成功均可');
} catch (error) {
  check('自定义段内 10.255.255.1 放行', String(error.message).includes('not a public address'), false);
}

/* 4. 真实网络（提示性，不计入退出码） ------------------------------------- */

const live = new LanFetchProvider({ v4: DEFAULTS.fakeIpRanges, v6: DEFAULTS.fakeIpRanges6 });
try {
  const result = await live.fetch({ url: 'https://example.com/' });
  console.log(`INFO  真实抓取 https://example.com/ => HTTP ${result.statusCode}, ${result.body.content.length} 字符`);
} catch (error) {
  console.log(`INFO  真实抓取跳过（${error.message}）—— 代理未开时属正常`);
}

console.log(failed === 0 ? '\n全部通过' : `\n${failed} 项失败`);
// 不用 process.exit()：Windows 上管道里还有未刷完的 stdout 时强行退出会触发
// libuv 的 UV_HANDLE_CLOSING 断言。设置 exitCode 让事件循环自然结束。
process.exitCode = failed === 0 ? 0 : 1;
