# ad-domains

从 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 的 `adblockdnslite.txt` 提取的**纯域名屏蔽列表**，每天自动同步，并已剔除源列表中声明的白名单域名。

适用于 AdGuard Home、dnsmasq、SmartDNS、mosdns 等直接消费"每行一个域名"的工具。

## 订阅地址

以下均为本仓库（`aisubing/ad-domains`，`main` 分支）的 raw 直链，可直接填入 AdGuard Home 等工具的上游订阅框，按需选择其一：

### 标准版（推荐）

仅剔除与白名单直接冲突的条目，拦截更全：

```
https://raw.githubusercontent.com/aisubing/ad-domains/main/output/ad-domains.txt
```

### Lite 版

白名单域名同主域的屏蔽条目已全部移除，更保守、误杀更少：

```
https://raw.githubusercontent.com/aisubing/ad-domains/main/output/ad-domainslite.txt
```

### 白名单

源列表中的白名单域名，供支持例外/允许列表的工具配合屏蔽列表使用：

```
https://raw.githubusercontent.com/aisubing/ad-domains/main/output/ad-whitelist.txt
```

## 它做了什么

1. 下载源列表 [adblockdnslite.txt](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt)（Lite 版仅针对国内域名拦截，每 8 小时更新）；
2. 解析 `||example.com^`（屏蔽）与 `@@||example.com^`（白名单）两类规则，只保留可解析为纯域名的行；
3. `ad-domains.txt` 从屏蔽列表中剔除（如果存在）：
   - 与白名单条目**完全相同**的域名（如 `sax.sina.com.cn`）；
   - 白名单条目的**子域名**；
   - 白名单条目的**父域名**（如源列表屏蔽了 `doubleclick.net`，但白名单放行了 `pagead.l.doubleclick.net`——DNS 工具通常将条目连同子域名一起拦截，保留父域名会让白名单失效）；
4. `ad-domainslite.txt` 是更保守的 Lite 版：**出现在白名单中的域名，其同主域的屏蔽条目全部移除**。主域按 [Public Suffix List](https://publicsuffix.org/) 计算（脚本运行时自动下载），例如白名单放行 `captcha.su.baidu.com`（主域 `baidu.com`），则屏蔽列表中所有 `*.baidu.com` 条目一并移除，进一步降低误杀；
5. 去重、排序后输出：每个域名文件**首行为 `#` 时间标识**（最后更新时间与源版本号，随内容更新刷新），其余每行一个纯域名。AdGuard Home 等工具会忽略 `#` 注释行；若所用工具要求严格纯域名，请自行过滤 `#` 开头的行。

脚本内置两道防护，防止上游异常导致列表被清空：任一结果少于 1000 个域名、或较上次跌幅超过 50% 时，拒绝写出并让任务失败。

## 输出文件

| 文件 | 说明 |
| --- | --- |
| `output/ad-domains.txt` | 纯域名屏蔽列表，仅剔除与白名单直接冲突的条目 |
| `output/ad-domainslite.txt` | Lite 版：白名单域名同主域的屏蔽条目已全部移除（更保守、误杀更少） |
| `output/ad-whitelist.txt` | 源列表中的白名单域名（供支持例外列表的工具使用） |
| `output/stats.json` | 源版本号、各阶段计数、被剔除域名与白名单主域明细 |

## 每日自动同步

GitHub Actions 定时任务（见 [.github/workflows/sync.yml](.github/workflows/sync.yml)）：

- 每天北京时间 **02:00**（UTC 18:00）自动运行，**仅当域名内容有变化时才提交**（首行时间标识随内容更新刷新，无变化的日子不产生提交）；
- 也支持手动触发：仓库页面 **Actions → Sync Domains → Run workflow**；
- 修改脚本或 workflow 后 push 也会自动运行一次，便于验证改动。

如需修改同步时间，调整 `sync.yml` 中的 `cron`（注意是 UTC，北京时间需减 8 小时）。

## 本地运行

仅需 Python 3.10+，无第三方依赖：

```bash
python scripts/extract_domains.py           # 下载最新源列表并生成 output/
python scripts/extract_domains.py <file>    # 使用本地文件作为源（离线测试）
```

## 目录结构

```
ad-domains/
├── .github/workflows/sync.yml   # 每日定时同步
├── scripts/extract_domains.py   # 提取与过滤脚本
└── output/                      # 生成的纯域名列表（自动提交）
```

## 致谢

- [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) —— 上游规则源及其引用的各规则列表维护者。

## 许可

[MIT](LICENSE)
