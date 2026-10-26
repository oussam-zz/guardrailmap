"""guardrailmap —— 自检测试。

把散落在代码与提示词里的约束整理成清单，标出未覆盖与相互冲突的条目。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import guardrailmap  # noqa: E402


class TestGuardrailMap(unittest.TestCase):
    def test_declared_but_not_implemented_is_found(self):
        declared = "- 禁止输出用户密钥\n- 不得访问外部网络\n"
        source = "# 这里只有一点普通代码\nprint('hello')\n"
        r = guardrailmap.build_map(declared, source)
        self.assertGreater(r["summary"]["uncovered_count"], 0)

    def test_implemented_but_not_declared_is_found(self):
        declared = "- 必须脱敏输出\n"
        source = "- 禁止输出用户密钥\n"
        r = guardrailmap.build_map(declared, source)
        self.assertGreater(r["summary"]["undeclared_count"], 0)

    def test_high_risk_category_detection(self):
        declared = "- 禁止在日志里打印 API key\n"
        r = guardrailmap.build_map(declared, "")
        self.assertEqual(r["declared"][0]["risk"], "敏感信息")

    def test_conflicting_constraints_are_found(self):
        declared = "- 禁止包含个人信息\n- 必须包含用户姓名\n"
        r = guardrailmap.build_map(declared, "")
        self.assertGreaterEqual(r["summary"]["conflict_count"], 1)

    def test_does_not_judge_reasonableness(self):
        """防呆：只做差集，不评价约束本身合不合理。"""
        declared = "- 禁止做某件完全不合理的事\n"
        r = guardrailmap.build_map(declared, "")
        self.assertNotIn("verdict", r)
        self.assertIn("declared", r)
