#!/usr/bin/env python3
"""ad-domain —— 从 217heidai/adblockfilters 的 adblockdnslite.txt 提取纯域名屏蔽列表。

处理逻辑：
  1. 下载源列表（https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt）；
  2. 解析 `||example.com^` 屏蔽规则与 `@@||example.com^` 白名单规则，校验域名合法性；
  3. 生成域名列表文件（首行为 “# Updated: ...” 时间标识，其余每行一个纯域名）：
     - ad-domains.txt：从屏蔽列表中剔除（“如果存在”）：
       * 与白名单条目完全相同；
       * 是某个白名单条目的子域名；
       * 是某个白名单条目的父域名——DNS 工具通常将条目连同子域名一起拦截，
         保留父域名会让白名单域名继续被封锁；
     - ad-domainslite.txt：更保守的 Lite 版——出现在白名单中的域名，其同主域的
       屏蔽条目全部移除。主域按 Public Suffix List 计算，如白名单放行
       captcha.su.baidu.com（主域 baidu.com），则屏蔽列表中所有 *.baidu.com 一并移除；
     - ad-whitelist.txt：源列表中的白名单域名；
  4. 去重、排序后输出。域名内容与上次一致时不重写任何文件（含统计），
     首行时间标识保持上次更新时间，避免无效提交。

防护措施：
  - 任一结果低于 MIN_DOMAINS 或较上次跌幅超过 DROP_RATIO 时拒绝写出，防止上游异常清空列表。

用法：
  python scripts/extract_domains.py            # 下载最新源列表并生成 output/
  python scripts/extract_domains.py <file>     # 使用本地文件作为源（离线测试）
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "output"

DOWNLOAD_TIMEOUT = 30
DOWNLOAD_RETRIES = 3
RETRY_INTERVAL = 10

MIN_DOMAINS = 1000  # 低于该数量视为源异常，拒绝写出
DROP_RATIO = 0.5    # 较上次结果跌幅超过该比例视为异常，拒绝写出

# `||example.com^` / `@@||example.com^`，允许 `^` 后带 $选项；域名外的字符不匹配
RULE_RE = re.compile(r"^(@@)?\|\|([A-Za-z0-9.-]+)\^(?:\$.*)?$")
LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")

# PSL 下载失败时的兜底：常见多级公共后缀（正常情况下不会用到）
FALLBACK_PSL = """
com.cn net.cn org.cn gov.cn edu.cn ac.cn mil.cn
com.hk net.hk org.hk gov.hk edu.hk idv.hk com.tw net.tw org.tw gov.tw edu.tw idv.tw
com.mo net.mo org.mo gov.mo edu.mo co.uk org.uk gov.uk ac.uk me.uk ltd.uk plc.uk net.uk sch.uk
com.au net.au org.au gov.au edu.au idv.au asn.au co.jp ne.jp or.jp go.jp ac.jp ad.jp ed.jp gr.jp lg.jp
co.kr ne.kr or.kr go.kr ac.kr re.kr pe.kr co.in net.in org.in firm.in gen.in ind.in res.in ac.in edu.in gov.in mil.in
com.br net.br org.br gov.br edu.br com.mx net.mx org.mx gob.mx edu.mx
com.sg net.sg org.sg gov.sg edu.sg com.my net.my org.my gov.my edu.my
co.th in.th or.th go.th ac.th net.th com.tr net.tr org.tr gov.tr edu.tr
com.ar net.ar org.ar gob.ar edu.ar com.co net.co org.co gov.co edu.co
com.vn net.vn org.vn gov.vn edu.vn com.ph net.ph org.ph gov.ph edu.ph
com.pk net.pk org.pk gov.pk edu.pk com.bd net.bd org.bd gov.bd edu.bd
com.ng net.ng org.ng gov.ng edu.ng com.eg net.eg org.eg gov.eg edu.eg
com.sa net.sa org.sa gov.sa edu.sa co.za net.za org.za web.za gov.za ac.za
co.id or.id web.id net.id go.id ac.id sch.id com.pe net.pe org.pe gob.pe edu.pe
""".split()


def log(msg: str) -> None:
    print(msg, flush=True)


def fetch_source(url: str) -> str:
    last_err: Exception | None = None
    for attempt in range(1, DOWNLOAD_RETRIES + 1):
        try:
            with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            log(f"下载失败（第 {attempt}/{DOWNLOAD_RETRIES} 次）：{exc}")
            if attempt < DOWNLOAD_RETRIES:
                time.sleep(RETRY_INTERVAL)
    raise SystemExit(f"无法下载 {url}：{last_err}")


def is_valid_domain(domain: str) -> bool:
    if len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    return all(len(label) <= 63 and LABEL_RE.match(label) for label in labels)


def ancestors(domain: str) -> set[str]:
    """返回 domain 的全部真父域，如 a.b.c.com -> {b.c.com, c.com}。"""
    labels = domain.split(".")
    return {".".join(labels[i:]) for i in range(1, len(labels))}


def write_lines(path: Path, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def write_list(path: Path, lines: list[str], header_line: str) -> None:
    """写入带首行时间标识的域名列表，其余每行一个纯域名。"""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(header_line + "\n" + "\n".join(lines) + "\n")


def write_list_if_changed(path: Path, lines: list[str], header_line: str) -> bool:
    """域名内容与现有文件一致时保持原文件不动（保留原时间标识），否则重写。"""
    if path.exists():
        existing = path.read_text(encoding="utf-8").splitlines()
        if existing and existing[0].startswith("#") and existing[1:] == lines:
            return False
    write_list(path, lines, header_line)
    return True


def parse_psl(text: str) -> tuple[set[tuple[str, ...]], set[tuple[str, ...]], dict[tuple[str, ...], int]]:
    """解析 Public Suffix List，返回（普通规则，例外规则，通配符规则）。"""
    rules: set[tuple[str, ...]] = set()
    exceptions: set[tuple[str, ...]] = set()
    for raw in text.splitlines():
        line = raw.strip().lower().rstrip(".")
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(tuple(line[1:].split(".")))
        else:
            rules.add(tuple(line.split(".")))
    wildcards = {r[1:]: len(r) for r in rules if r[0] == "*"}
    return rules, exceptions, wildcards


def load_psl() -> tuple[set[tuple[str, ...]], set[tuple[str, ...]], dict[tuple[str, ...], int]]:
    try:
        rules, exceptions, wildcards = parse_psl(fetch_source(PSL_URL))
    except SystemExit as exc:
        log(f"警告：{exc}；退回内置常见多级后缀判断主域，同主域剔除可能不完整")
        rules = {tuple(s.split(".")) for s in FALLBACK_PSL}
        return rules, set(), {}
    log(f"已下载 Public Suffix List：{len(rules)} 条规则、{len(wildcards)} 条通配符")
    return rules, exceptions, wildcards


def base_domain(
    domain: str,
    rules: set[tuple[str, ...]],
    exceptions: set[tuple[str, ...]],
    wildcards: dict[tuple[str, ...], int],
) -> str:
    """按 PSL 算法返回 domain 的主域（registrable domain），如 sax.sina.com.cn -> sina.com.cn。"""
    labels = domain.split(".")
    n = len(labels)
    suffix_len = 1  # 默认规则：任意单标签 TLD
    for i in range(n):
        if tuple(labels[i:]) in exceptions:  # 例外规则：!www.ck 命中时后缀长度减一
            suffix_len = max(1, n - i - 1)
            break
    else:
        for i in range(n):
            if tuple(labels[i:]) in rules:
                suffix_len = max(suffix_len, n - i)
        for k in range(2, n + 1):
            if wildcards.get(tuple(labels[n - k + 1:])) == k:
                suffix_len = max(suffix_len, k)
    if suffix_len >= n:  # 域名本身即公共后缀等极端情况，退回自身
        return domain
    return ".".join(labels[n - suffix_len - 1:])


def main() -> None:
    local_path = sys.argv[1] if len(sys.argv) > 1 else None
    if local_path:
        log(f"使用本地源文件：{local_path}")
        text = Path(local_path).read_text(encoding="utf-8", errors="replace")
    else:
        log(f"下载源列表：{SOURCE_URL}")
        text = fetch_source(SOURCE_URL)

    blocked: set[str] = set()
    whitelisted: set[str] = set()
    header: dict[str, str] = {}
    skipped = 0

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("!"):
            # 抓取头部元信息，如 “! Version: 20261012040542”
            key, sep, value = line[1:].partition(":")
            if sep and key.strip() in ("Version", "Last modified"):
                header.setdefault(key.strip(), value.strip())
            continue
        m = RULE_RE.match(line)
        domain = m.group(2).lower() if m else ""
        if not m or not is_valid_domain(domain):
            skipped += 1
            log(f"跳过无法解析为纯域名的行：{line}")
            continue
        (whitelisted if m.group(1) else blocked).add(domain)

    log(f"解析完成：屏蔽 {len(blocked)}，白名单 {len(whitelisted)}，跳过 {skipped} 行")

    if len(blocked) < MIN_DOMAINS:
        raise SystemExit(f"解析到 {len(blocked)} 个屏蔽域名，低于 {MIN_DOMAINS}，疑似源异常，已中止。")

    # ad-domains.txt：剔除与白名单直接冲突的条目
    removed_exact = blocked & whitelisted
    removed_sub = {d for d in blocked if d not in removed_exact and ancestors(d) & whitelisted}
    removed_parent = {
        d
        for d in blocked
        if d not in removed_exact and d not in removed_sub and any(w.endswith("." + d) for w in whitelisted)
    }
    final = sorted(blocked - removed_exact - removed_sub - removed_parent)

    # ad-domainslite.txt：白名单域名同主域的屏蔽条目全部移除
    psl = load_psl()
    whitelist_bases = sorted({base_domain(w, *psl) for w in whitelisted})
    base_set = set(whitelist_bases)
    lite = sorted(d for d in blocked if base_domain(d, *psl) not in base_set)

    # 与上次结果对比，防止上游异常导致清空列表
    stats_path = OUTPUT_DIR / "stats.json"
    prev_final = prev_lite = 0
    if stats_path.exists():
        try:
            prev_counts = json.loads(stats_path.read_text(encoding="utf-8"))["counts"]
            prev_final = int(prev_counts["final_domains"])
            prev_lite = int(prev_counts.get("lite_domains", 0))
        except Exception:  # noqa: BLE001
            prev_final = prev_lite = 0
    if prev_final and len(final) < prev_final * DROP_RATIO:
        raise SystemExit(f"域名数 {len(final)} 较上次 {prev_final} 跌幅超过 {DROP_RATIO:.0%}，疑似源异常，已中止。")
    if prev_lite and len(lite) < prev_lite * DROP_RATIO:
        raise SystemExit(f"Lite 域名数 {len(lite)} 较上次 {prev_lite} 跌幅超过 {DROP_RATIO:.0%}，疑似源异常，已中止。")

    generated_at = datetime.now(timezone.utc)
    header_line = f"# Updated: {generated_at:%Y-%m-%d %H:%M} UTC"
    if header.get("Version"):
        header_line += f" | Source version: {header['Version']}"

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    changed = (
        write_list_if_changed(OUTPUT_DIR / "ad-domains.txt", final, header_line)
        | write_list_if_changed(OUTPUT_DIR / "ad-domainslite.txt", lite, header_line)
        | write_list_if_changed(OUTPUT_DIR / "ad-whitelist.txt", sorted(whitelisted), header_line)
    )

    stats = {
        "source_url": SOURCE_URL,
        "source_version": header.get("Version", ""),
        "source_last_modified": header.get("Last modified", ""),
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "source_lines": len(text.splitlines()),
            "skipped_lines": skipped,
            "blocked": len(blocked),
            "whitelist": len(whitelisted),
            "removed_exact": len(removed_exact),
            "removed_subdomain": len(removed_sub),
            "removed_parent": len(removed_parent),
            "final_domains": len(final),
            "lite_domains": len(lite),
            "removed_related": len(blocked) - len(lite),
        },
        "removed": {
            "exact": sorted(removed_exact),
            "subdomain_of_whitelist": sorted(removed_sub),
            "parent_of_whitelist": sorted(removed_parent),
        },
        "whitelist_base_domains": whitelist_bases,
    }
    if changed:
        write_lines(stats_path, [json.dumps(stats, ensure_ascii=False, indent=2)])
    else:
        log("域名内容与上次一致，跳过重写与统计更新")

    log(
        f"已生成 {OUTPUT_DIR / 'ad-domains.txt'}：{len(final)} 个域名"
        f"（剔除与白名单相同 {len(removed_exact)}、白名单子域名 {len(removed_sub)}、"
        f"白名单父域名 {len(removed_parent)}）"
    )
    log(
        f"已生成 {OUTPUT_DIR / 'ad-domainslite.txt'}：{len(lite)} 个域名"
        f"（白名单同主域剔除 {len(blocked) - len(lite)}，涉及主域 {len(whitelist_bases)} 个）"
    )


if __name__ == "__main__":
    main()
