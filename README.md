# xray2mihomo

将 Xray 配置（jsonc）或 vless 分享链接转换为 Mihomo（Clash Meta）的 `proxies:` 配置片段。纯 Python 标准库，零依赖。

## 用法

```bash
python xray2mihomo.py 输入文件 [-o 输出.yaml]
```

- 无 `-o` 时输出到 stdout
- 输出为 `proxies:` 片段，可直接合并进自己的 mihomo 配置

## 支持的输入

单个输入文件可混用以下两种内容，脚本逐行自动识别：

1. **Xray jsonc 配置** — 读取 `outbounds`，其他部分忽略
2. **vless:// 分享链接** — 每行一个

## 支持范围

| 输入 | 协议 | 传输层 | 加密 |
|---|---|---|---|
| jsonc outbound | vless | xhttp / ws | reality / tls |
| share link | vless:// | type=xhttp / type=ws | security=reality / tls |

- `freedom` / `blackhole` 出站（直连/block）自动跳过
- 其他协议（vmess、trojan、ss 等）、其他传输层或组合（如 ws+reality）报错退出，错误信息含 outbound tag 或链接行号

## 字段映射

### jsonc outbound → proxy

| mihomo 字段 | 来源 |
|---|---|
| server / port | `settings.vnext[0].address` / `.port` |
| uuid | `settings.vnext[0].users[0].id` |
| network | `streamSettings.network` |
| servername | `realitySettings.serverName` 或 `tlsSettings.serverName` |
| client-fingerprint | `realitySettings.fingerprint` 或 `tlsSettings.fingerprint` |
| reality-opts | `realitySettings.publicKey` → public-key、`shortId` → short-id |
| alpn | `tlsSettings.alpn` |
| xhttp/ws-opts | `xhttpSettings` / `wsSettings` 的 path、host、mode |

### share link → proxy

| mihomo 字段 | 链接参数 |
|---|---|
| server / port / uuid | `UUID@server:port` |
| network | `type` |
| servername | `sni` |
| client-fingerprint | `fp` |
| reality-opts | `pbk` → public-key、`sid` → short-id |
| alpn | `alpn`（可重复参数） |
| xhttp/ws-opts | `path`、`host`、`mode`（自动百分号解码） |

`encryption`、`insecure`、`allowInsecure`、`spx` 等参数已解析但暂不输出。

## 节点命名

- 分享链接：优先使用 `#fragment`（如 `v2-xhttp-reality`）
- jsonc：`传输层+加密方式`（如 `xhttp-reality`、`ws-tls`）
- 重名自动追加后缀：`xhttp-reality2`、`xhttp-reality3` …

## 示例

```bash
python xray2mihomo.py example/share-link.txt
```

```yaml
proxies:
- name: "example-node"
  type: vless
  server: node1.example.com
  port: 443
  uuid: 9a7f3c2e-5d41-4b8a-9e6c-1f2a3b4c5d6e
  udp: true
  tls: true
  network: xhttp
  reality-opts:
    public-key: FAKE_PUBLIC_KEY_VALUE_123
    short-id: deadbeefcafef00d
  servername: www.example.com
  client-fingerprint: chrome
  encryption: ""
  xhttp-opts:
    path: "/example-path"
    mode: "stream-one"
```




## 扩展

新增协议支持：在 `CONVERTERS` 注册表中注册一个转换函数，输入 outbound dict，输出与现有 proxy dict 同构的 dict 即可。
