#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
提交前守門：擋住個資與資料檔進到這個 PUBLIC repo。

零依賴（只用 Python 3 標準函式庫）。

設計上的三個堅持
--------------------------------------------------------------------
1. 看的是「暫存區的內容」（git show :path），不是工作目錄的檔案。
   會被 commit 的是暫存區那一份，守門就該看那一份。

2. 母體斷言（population assertion）。
   一支只比差集的守門，在掃描目標變空時會「誠實地回報通過」——
   它沒說謊，它只是瞎了。所以這裡每一輪都自我檢查：
     a. 規則數量 < MIN_RULES        -> 失敗（規則母體縮小了）
     b. 自我測試沒有全部命中        -> 失敗（偵測器壞了）
     c. 暫存檔案數 != 實際處理數    -> 失敗（視野縮小了）
   任何一項不成立就 exit 1，寧可擋錯也不要靜靜放行。

3. 不印出命中的原文。
   守門的輸出如果照抄個資，守門本身就是第二次外洩。
   一律遮蔽後才輸出。

安裝：  git config core.hooksPath .githooks
單獨跑：python3 .githooks/pii_guard.py --selftest
        python3 .githooks/pii_guard.py --scan-paths <檔案...>
"""

import os
import re
import subprocess
import sys

# ── 門檻 ────────────────────────────────────────────────────────────
MAX_TABULAR_ROWS = 50           # 超過這麼多列的表格檔一律擋
MAX_FILE_BYTES = 5 * 1024 * 1024  # 單檔超過 5 MiB 一律擋
MIN_RULES = 7                   # 母體斷言：規則不得少於這個數
SNIFF_BYTES = 200_000           # 表格偵測最多讀這麼多位元組

TABULAR_EXT = {".csv", ".tsv", ".psv", ".txt", ""}
DELIMITERS = [",", "\t", "|", ";"]

# ── 規則 ────────────────────────────────────────────────────────────
# 每條規則寫成 regex；規則本身不會命中自己（用的是 \d{n} 這種樣式，
# 不是字面上的數字）。SECRET 那條刻意要求「有引號、有 8 字以上的值」，
# 這樣這個檔案裡出現的 "token" / "secret" 等字眼才不會誤炸自己。
RULES = [
    ("EMAIL",
     re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("TW_MOBILE",
     re.compile(r"(?<![0-9])(?:\+?886[\-\s]?9|09)\d{2}[\-\s]?\d{3}[\-\s]?\d{3}(?![0-9])")),
    ("TW_LANDLINE",
     re.compile(r"(?<![0-9])0[2-8][\-\s)]?\d{4}[\-\s]?\d{4}(?![0-9])")),
    ("TW_NATIONAL_ID",
     re.compile(r"(?<![A-Za-z0-9])[A-Z][12]\d{8}(?![A-Za-z0-9])")),
    ("CREDIT_CARD",
     re.compile(r"(?<![0-9])(?:\d[ \-]?){12,18}\d(?![0-9])")),
    ("SECRET_ASSIGN",
     re.compile(r"""(?i)\b(?:api[_\-]?key|secret|token|password|passwd|auth)\b\s*[:=]\s*['"][^'"\s]{8,}['"]""")),
    ("PROVIDER_TOKEN",
     re.compile(r"(?:AIza[0-9A-Za-z_\-]{30,}"
                r"|sk-[A-Za-z0-9]{32,}"
                r"|ghp_[A-Za-z0-9]{30,}"
                r"|EAA[A-Za-z0-9]{60,}"
                r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
]

# 已遮蔽的示範文字不該被當成命中（報告裡到處都是這種寫法）
MASKED = re.compile(r"[*xX]{2,}|…|\bxxx\b", re.IGNORECASE)


def luhn_ok(digits: str) -> bool:
    """信用卡號用 Luhn 檢查，把一般長數字串（訂單號、時間戳）濾掉。"""
    d = [int(c) for c in digits if c.isdigit()]
    if not (13 <= len(d) <= 19):
        return False
    total, alt = 0, False
    for n in reversed(d):
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def mask(s: str) -> str:
    """輸出用遮蔽：保留頭一個字元與長度感，其餘蓋掉。"""
    s = s.strip()
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + "*" * (len(s) - 2) + s[-1] if len(s) <= 6 else s[:2] + "*" * (len(s) - 2)


def scan_text(name: str, text: str):
    """回傳 [(規則, 行號, 遮蔽後片段)]"""
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for rule, rx in RULES:
            for m in rx.finditer(line):
                raw = m.group(0)
                if MASKED.search(raw):
                    continue                      # 已遮蔽的示範，放行
                if rule == "CREDIT_CARD" and not luhn_ok(raw):
                    continue
                hits.append((rule, lineno, mask(raw)))
                break                             # 同一行同一規則報一次就夠
    return hits


def tabular_rows(name: str, text: str):
    """
    偵測「這是不是一張表」。刻意不只看副檔名——
    真實案例裡最大的那份名單根本沒有副檔名。
    回傳資料列數；不是表格就回傳 None。
    """
    lines = [l for l in text.split("\n", 400)[:400] if l.strip()]
    if len(lines) < 3:
        return None
    for d in DELIMITERS:
        counts = [l.count(d) for l in lines[:20]]
        if counts[0] >= 2 and len(set(counts)) <= 2 and min(counts) >= 2:
            return text.count("\n")
    ext = os.path.splitext(name)[1].lower()
    if ext in (".csv", ".tsv") and len(lines) >= 3:
        return text.count("\n")
    return None


def staged_paths():
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        capture_output=True, text=True, check=True).stdout
    return [p for p in out.split("\0") if p]


def staged_blob(path: str):
    r = subprocess.run(["git", "show", f":{path}"], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def selftest() -> bool:
    """
    反向驗證：用**自己編的假資料**確認每條規則真的會紅。
    字串刻意用拼接組出來，這樣這個檔案本身被 commit 時不會炸到自己
    ——不是為了好看，是為了不必用「路徑白名單」放自己過，
    因為白名單正是守門變瞎的第一步。
    """
    fixtures = {
        "EMAIL":           "no" + "body" + "@examp" + "le.com",
        "TW_MOBILE":       "091" + "2345" + "678",
        "TW_LANDLINE":     "02-" + "8765" + "4321",
        "TW_NATIONAL_ID":  "A1" + "2345" + "6789",
        "CREDIT_CARD":     "4539" + "1488" + "0343" + "6467",   # Luhn 合法的測試卡號
        "SECRET_ASSIGN":   'api_key = "' + "abcd" + "efgh1234" + '"',
        "PROVIDER_TOKEN":  "ghp_" + "A" * 34,
    }
    ok = True
    if len(RULES) < MIN_RULES:
        print(f"  [自我測試] 規則母體縮小了：{len(RULES)} < {MIN_RULES}")
        return False
    for rule, _ in RULES:
        sample = fixtures.get(rule)
        if sample is None:
            print(f"  [自我測試] 規則 {rule} 沒有對應的假資料樣本 —— 補上再說")
            ok = False
            continue
        if not scan_text("selftest", sample):
            print(f"  [自我測試] 規則 {rule} 沒有命中它自己的假資料 —— 偵測器壞了")
            ok = False
    # 反向的反向：已遮蔽的寫法必須放行，否則報告本身會被擋下來
    for masked in ("a***@gmail.com", "09xx-xxx-123", "使用者 UAFL4****"):
        if scan_text("selftest", masked):
            print(f"  [自我測試] 遮蔽後的示範被誤判成個資：{masked}")
            ok = False
    # 表格偵測也要驗：50 列以上要被認出來，而且不靠副檔名
    fake_table = "\n".join("欄A,欄B,欄C" for _ in range(MAX_TABULAR_ROWS + 5))
    if (tabular_rows("no_extension_file", fake_table) or 0) <= MAX_TABULAR_ROWS:
        print("  [自我測試] 無副檔名的大表格沒有被認出來")
        ok = False
    return ok


def main(argv):
    if "--selftest" in argv:
        print("PII 守門 · 自我測試")
        good = selftest()
        print("  結果：" + ("全部命中，偵測器正常" if good else "有規則失效"))
        return 0 if good else 1

    if "--scan-paths" in argv:
        paths = argv[argv.index("--scan-paths") + 1:]
        read = lambda p: open(p, "rb").read()
    else:
        paths = staged_paths()
        read = staged_blob

    # ── 母體斷言 (a)(b)：規則與偵測器先自我驗證，壞了就不准 commit ──
    if not selftest():
        print("\n✗ 守門的自我測試沒過。在修好之前不放行任何 commit。", file=sys.stderr)
        return 1

    if not paths:
        print("PII 守門：暫存區沒有檔案，略過。")
        return 0

    problems = []
    accounted = 0

    for p in paths:
        data = read(p)
        if data is None:
            problems.append((p, "UNREADABLE", 0, "讀不到暫存區內容"))
            accounted += 1
            continue

        if len(data) > MAX_FILE_BYTES:
            problems.append((p, "FILE_TOO_LARGE", 0,
                             f"{len(data)/1048576:.1f} MiB 超過 {MAX_FILE_BYTES/1048576:.0f} MiB"))
            accounted += 1
            continue

        if b"\0" in data[:8000]:
            accounted += 1          # 二進位檔（圖片等）：不做文字掃描，但有算進母體
            continue

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", "replace")

        rows = tabular_rows(p, text[:SNIFF_BYTES])
        if rows is not None and rows > MAX_TABULAR_ROWS:
            problems.append((p, "TABULAR_DATA", 0,
                             f"看起來是表格，約 {rows} 列（上限 {MAX_TABULAR_ROWS}）"))

        for rule, lineno, snippet in scan_text(p, text)[:5]:
            problems.append((p, rule, lineno, snippet))

        accounted += 1

    # ── 母體斷言 (c)：進去幾個就要出來幾個 ──
    if accounted != len(paths):
        print(f"\n✗ 視野縮小了：暫存 {len(paths)} 個檔案，只處理了 {accounted} 個。",
              file=sys.stderr)
        print("  守門不能對自己沒看過的東西說「通過」。", file=sys.stderr)
        return 1

    if problems:
        print("\n╭─ PII 守門攔下了這次 commit " + "─" * 30, file=sys.stderr)
        for p, rule, lineno, detail in problems:
            loc = f"{p}:{lineno}" if lineno else p
            print(f"│  [{rule}] {loc}", file=sys.stderr)
            print(f"│      {detail}", file=sys.stderr)
        print("│", file=sys.stderr)
        print("│  這個 repo 是 PUBLIC —— push 出去就收不回來了。", file=sys.stderr)
        print("│  確定是誤判的話：git commit --no-verify（請先想三秒）", file=sys.stderr)
        print("╰" + "─" * 56, file=sys.stderr)
        return 1

    print(f"PII 守門：{len(paths)} 個檔案全數檢查完畢，沒有發現個資或資料檔。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
