"""guardrailmap —— 把安全约束画成一张可核对的清单。

设计原则：
1. **声明与现实要对得上**。写在文档里的约束和代码里真正生效的约束，
   经常已经是两份东西。
2. **只做差集**。不判断约束合不合理，只检查声明与现实对不对得上。
3. **冲突要标出来**。两条互斥的约束同时存在时，实际生效的是哪条，
   得让人去确认。

仅依赖 Python 标准库。

用法:
    python guardrailmap.py --help
    python guardrailmap.py --declared guards.md --source app.py
    python guardrailmap.py --declared guards.md --source app.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys

# ---------------------------------------------------------------------------
# 约束识别
# ---------------------------------------------------------------------------

# 约束的措辞特征
CONSTRAINT_PATTERNS = [
    ("禁止", re.compile(r"(禁止|不得|不可|严禁|不要|never|must not|forbidden|"
                        r"disallow)", re.I)),
    ("必须", re.compile(r"(必须|应当|需要|要|must|required|require|ensure)", re.I)),
    ("限制", re.compile(r"(最多|不超过|至多|至少|不少于|上限|下限|"
                        r"at most|at least|max|min)", re.I)),
    ("范围", re.compile(r"(仅|只|限于|范围|only|limited to|within)", re.I)),
]

# 从一段文字里抽出「约束对象」：紧跟在约束词后面的一小段
OBJECT_RE = re.compile(
    r"(?:禁止|不得|不可|严禁|不要|必须|应当|需要|最多|不超过|至多|至少|不少于|"
    r"仅|只|限于|不得包含|必须包含|不应)"
    r"\s*[^\n。，,；;]{0,24}")

# 高危类别：这些约束的缺失或冲突影响更大
HIGH_RISK = (
    ("注入防护", re.compile(r"(注入|injection|prompt\s*injection)", re.I)),
    ("越权访问", re.compile(r"(越权|越界|权限|授权|authz|authoriz|access\s*control)",
                            re.I)),
    ("敏感信息", re.compile(r"(敏感|脱敏|redact|pii|个人信息|姓名|身份证|手机号|邮箱|"
                            r"密钥|secret|credential|password|api[\s_-]*key)", re.I)),
    ("执行限制", re.compile(r"(执行|运行|exec|shell|命令)", re.I)),
    ("输出限制", re.compile(r"(输出|泄露|disclosure|leak)", re.I)),
)


def extract_constraints(text: str) -> list[dict]:
    """从一段文字里抽出约束条目。"""
    out: list[dict] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # 去掉列表符号
        line = re.sub(r"^\s*(?:[-*+]|\d+[.)])\s+", "", line)
        if not line:
            continue

        kinds = [k for k, pat in CONSTRAINT_PATTERNS if pat.search(line)]
        if not kinds:
            continue

        m = OBJECT_RE.search(line)
        obj = m.group(0) if m else line[:24]

        risk = ""
        for label, pat in HIGH_RISK:
            if pat.search(line):
                risk = label
                break

        out.append({
            "line": lineno,
            "text": line,
            "object": obj,
            "kinds": kinds,
            "risk": risk,
        })
    return out


# ---------------------------------------------------------------------------
# 冲突判定
# ---------------------------------------------------------------------------

# 同一对象上的互斥要求
CONFLICT_PAIRS = [
    (re.compile(r"(禁止|不得|不可|严禁|不要)"), re.compile(r"(必须包含|必须使用|必须|需要)"),
     "同一个对象既被禁止又被要求"),
    (re.compile(r"(最多|不超过|至多|上限)"), re.compile(r"(至少|不少于|下限)"),
     "上下限要求可能互相矛盾"),
    (re.compile(r"(仅|只允许|只)"), re.compile(r"(任何|全部|所有)"),
     "「仅限」与「全部」互相冲突"),
]


def find_conflicts(constraints: list[dict]) -> list[dict]:
    """找互斥的约束。"""
    conflicts: list[dict] = []
    for i in range(len(constraints)):
        for j in range(i + 1, len(constraints)):
            a, b = constraints[i], constraints[j]
            for pa, pb, why in CONFLICT_PAIRS:
                if pa.search(a["text"]) and pb.search(b["text"]):
                    # 只在同一风险类别或同一对象上才判冲突
                    if a["risk"] and a["risk"] == b["risk"]:
                        conflicts.append({
                            "reason": why,
                            "a": a, "b": b,
                            "scope": a["risk"],
                        })
                        break
    return conflicts


# ---------------------------------------------------------------------------
# 覆盖差集
# ---------------------------------------------------------------------------

def coverage(declared: list[dict], actual: list[dict]) -> dict:
    """声明 vs 实现 的差集。"""
    def norm(s: str) -> str:
        return re.sub(r"[\s，。,、:：;；'\"\"「」()（）]", "", s).lower()

    declared_norm = [norm(c["object"]) for c in declared]
    actual_norm = [norm(c["object"]) for c in actual]

    uncovered: list[dict] = []
    for d in declared:
        key = norm(d["object"])
        # 声明里最长的一段能在实现里找到，就算覆盖
        covered = any(key and (key in a or a in key) for a in actual_norm)
        if not covered:
            uncovered.append(d)

    # 实现里有、声明里没有的：值得补进清单
    undeclared: list[dict] = []
    for a in actual:
        key = norm(a["object"])
        covered = any(key and (key in d or d in key) for d in declared_norm)
        if not covered:
            undeclared.append(a)

    # 风险类别覆盖
    declared_risks = {c["risk"] for c in declared if c["risk"]}
    actual_risks = {c["risk"] for c in actual if c["risk"]}
    all_risks = {label for label, _ in HIGH_RISK}
    missing_risks = sorted(all_risks - declared_risks)

    return {
        "uncovered": uncovered,
        "undeclared": undeclared,
        "missing_risk_categories": missing_risks,
        "declared_risks": sorted(declared_risks),
        "actual_risks": sorted(actual_risks),
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def build_map(declared_text: str, source_text: str) -> dict:
    declared = extract_constraints(declared_text)
    actual = extract_constraints(source_text)
    cov = coverage(declared, actual)
    conflicts = find_conflicts(declared) + find_conflicts(actual)

    return {
        "declared": declared,
        "actual": actual,
        "coverage": cov,
        "conflicts": conflicts,
        "summary": {
            "declared_count": len(declared),
            "actual_count": len(actual),
            "uncovered_count": len(cov["uncovered"]),
            "undeclared_count": len(cov["undeclared"]),
            "conflict_count": len(conflicts),
            "missing_risk_count": len(cov["missing_risk_categories"]),
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def render(result: dict) -> str:
    out: list[str] = []
    s = result["summary"]
    out.append("安全约束覆盖清单")
    out.append("=" * 60)
    out.append(f"声明约束 {s['declared_count']} 条 ｜ 实现中提取 {s['actual_count']} 条")
    out.append(f"声明了但实现里没找到：{s['uncovered_count']} 条")
    out.append(f"实现里有但清单没写：{s['undeclared_count']} 条")
    out.append(f"互相冲突：{s['conflict_count']} 条")
    out.append("")

    cov = result["coverage"]

    if cov["uncovered"]:
        out.append("声明了但实现里找不到对应约束：")
        for c in cov["uncovered"]:
            risk = f"  [{c['risk']}]" if c["risk"] else ""
            out.append(f"  · {c['text']}{risk}")
        out.append("")

    if cov["undeclared"]:
        out.append("实现里有但清单没写（建议补进清单）：")
        for c in cov["undeclared"]:
            risk = f"  [{c['risk']}]" if c["risk"] else ""
            out.append(f"  · {c['text']}{risk}")
        out.append("")

    if cov["missing_risk_categories"]:
        out.append("清单里完全没提到的风险类别：")
        for r in cov["missing_risk_categories"]:
            out.append(f"  · {r}")
        out.append("")

    if result["conflicts"]:
        out.append("互相冲突的约束：")
        for c in result["conflicts"]:
            out.append(f"  ! {c['reason']}"
                       f"{'（' + c['scope'] + '）' if c.get('scope') else ''}")
            out.append(f"    A: {c['a']['text']}")
            out.append(f"    B: {c['b']['text']}")
        out.append("")

    out.append("注：本工具只做声明与实现的对照，不判断约束本身是否合理。")
    return "\n".join(out).rstrip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="guardrailmap",
        description="把安全约束画成一张可核对的清单（仅依赖标准库）",
        epilog=(
            "示例：\n"
            "  python guardrailmap.py --declared guards.md --source app.py\n"
            "  python guardrailmap.py --declared guards.md --source app.py --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--declared", required=True, help="声明的安全清单文件")
    ap.add_argument("--source", required=True, help="实现源码（或多个，用逗号分隔）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    try:
        declared_text = open(args.declared, "r", encoding="utf-8").read()
    except OSError as e:
        print(f"读不了声明文件：{e}", file=sys.stderr)
        return 2

    chunks: list[str] = []
    for path in args.source.split(","):
        path = path.strip()
        if not path:
            continue
        try:
            chunks.append(open(path, "r", encoding="utf-8").read())
        except OSError as e:
            print(f"读不了源码 {path}：{e}", file=sys.stderr)
            return 2

    if not chunks:
        print("没有源码。", file=sys.stderr)
        return 2

    result = build_map(declared_text, "\n".join(chunks))

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print(render(result))
    s = result["summary"]
    return 1 if (s["uncovered_count"] or s["conflict_count"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
