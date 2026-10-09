# dsh-web-fetch-lan

让 DeepSeek Harness 的 `web_fetch` 在 Clash / mihomo 的 **fake-ip** 环境下正常工作：放行 fake-ip 段，同时保留对内网、回环、云元数据等地址的拦截。零依赖，无需构建。

## 它解决什么问题

DSH 的 `web_fetch` 自带 SSRF 防护：连接前先解析域名，只要解析结果里出现非公网地址就直接拒绝，报 `WEB_BLOCKED_URL`：

```
Error: URL hostname "example.com" resolves to a non-public IP address
```

而 Clash / mihomo 开启 TUN + `enhanced-mode: fake-ip` 后，**所有域名都会被解析到保留段**（默认 `198.18.0.0/15` 与 `2001:2::/64`）。这些地址在 `ipaddr.js` 眼里不是 `unicast`，于是所有抓取全被拦下——哪怕你本机上网完全正常。

结果就是：开着 TUN 时 `web_fetch` 几乎不可用，关掉 TUN 才能用。更麻烦的是 Windows 上可能同时向两个网卡查 DNS，一会儿返回 fake-ip、一会儿返回真实 IP，表现为**时好时坏、难以复现**。

## 它做了什么

提供一个替换用的 fetch provider（`id = http-lan`），判定规则只有一处不同：

| 解析结果 | 内置 provider | 本插件 |
| --- | --- | --- |
| 公网地址 | 放行 | 放行 |
| fake-ip 段（可配置） | **拒绝** | **放行** |
| 回环 / 私网 / 链路本地 / CGNAT / 组播 / 保留段 | 拒绝 | 拒绝 |

也就是只把「fake-ip 这一段」当作可用：它只在 TUN 内部有意义，连接会被 mihomo 按域名映射转发到你本来要访问的站点，**并不会真的连到 198.18.x.x 那台主机**。而 `127.0.0.1`、`192.168.x.x`、`169.254.169.254`、`[::1]` 等等依旧被挡住，本机服务、内网设备、云元数据端点不会因为装了这个插件而暴露。

顺带修掉一个实测问题：在 TUN + fake-ip 环境下，如果让 Node 按 DNS 原顺序（`verbatim`，IPv6 优先）连接，HTTPS 会**间歇性 `ECONNRESET`**（TCP 通、TLS 阶段被重置），连内置 provider 也躲不过。插件在 `apply()` 里把本进程的 DNS 结果顺序设为 `ipv4first`，实测连续 8/8 成功；这只是排序偏好，没有 A 记录时仍会走 AAAA。

## 安装

插件走 DSH 的插件管理器安装（不是 `dsh plugin` CLI——桌面版 profile 由 Electron 独占管理）：

1. 把本仓库放在任意目录，例如 `D:\repository\dsh-web-fetch-lan`；
2. 打开 DSH 侧栏 **插件** → **添加插件**，填入该目录的**绝对路径**，安装；
3. 若提示需要重启，就重启一次 DSH：provider 是宿主进程启动时装载的。

安装后 profile 的 `package.json` 会多出一条 `link:` 依赖与一个 bundle 条目。要卸载就回到插件页删除，内置 provider 立刻恢复。

> 相对路径会被安装器拒绝，填绝对路径。

## 配置

fake-ip 段在 loader 行的 `config` 里配置，默认值写在 [cordis.patch.yml](cordis.patch.yml)：

```yaml
- insert:
    - id: web-fetch-lan
      name: '@local/dsh-web-fetch-lan'
      config:
        fakeIpRanges:
          - 198.18.0.0/15
        fakeIpRanges6:
          - 2001:2::/64
          - fdfe:dcba:9876::/64
```

在 Clash Verge 里改了 `fake-ip-range` / `fake-ip-range6` 之后，把新段补进这里，重启 DSH 即可，不用改代码。

不想改本仓库文件的话，在 profile 层覆盖（`~/.dsh/profiles/<profile>/cordis.patch.yml`）：

```yaml
- id: web-fetch-lan
  config:
    fakeIpRanges: ['198.18.0.0/15']
    fakeIpRanges6: ['2001:2::/64']
```

容错规则：条目逐个做 CIDR 校验，**非法条目剔除后保留其余**；非数组、或全部非法时**回退内置默认段**并在日志告警——不会因为配置写错而静默放行一切。生效的段会在启动日志里打印一行：

```
[web-fetch-lan] fake-ip 段 v4=198.18.0.0/15 v6=2001:2::/64,fdfe:dcba:9876::/64
```

`cordis.patch.yml` 里另有一条把 `web` 条的 `fetchProvider` 固定为 `http-lan`：内置的 `web-fetch-http` 依然注册着，不显式指定会得到 `WEB_PROVIDER_AMBIGUOUS`。

## 自检

零依赖，直接跑：

```bash
node selftest.mjs
# 或
pnpm test
```

覆盖配置归一与回退、地址判定、provider 装配，以及 `127.0.0.1` / `169.254.169.254` / `[::1]` / `192.168.3.1` / `file:` / 带凭据 URL 仍被拒绝；末尾附带一次真实抓取（代理没开时只提示，不计入退出码）。

## 边界

与内置 provider 保持一致的行为与限制：

- **仅同源重定向**，最多 5 跳；跨源跳转（含 `http://` → `https://` 的协议升级）会拒绝并提示重试目标 URL；
- 响应上限 2 MiB，正文截断 200,000 字符；只接受文本类 `content-type`；
- 单次抓取 30 秒超时；
- URL 不允许携带凭据，只支持 `http:` / `https:`。

注意区分两种失败：`fetch failed` 是网络层错误（多半是代理节点本身不通），不是被 SSRF 拦截；被拦截时的报错会明确写 `not a public address` / `resolves to a non-public IP address`。

## 目录结构

```
index.js          插件本体：地址判定、抓取实现、apply()
cordis.patch.yml  bundle patch：注册 provider + 插入插件行 + fake-ip 段配置
selftest.mjs      自检脚本（零依赖）
package.json      dsh.bundle.patch 指向 cordis.patch.yml
```

## 许可

[MIT](LICENSE)
