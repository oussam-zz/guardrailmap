# guardrailmap

**把安全约束画成一张可核对的清单。**

`guardrailmap` —— 把散落在代码与提示词里的约束整理成清单，标出未覆盖与相互冲突的条目。

- 零依赖，Python 3.10+ 标准库即可运行
- 单文件，`guardrailmap.py` 拷走就能用
- 不联网、不写文件

<!-- ipos:install -->
## 安装

零依赖，Python 3.10+ 即可：

```bash
pip install oussam-zz-guardrailmap
```

装完直接用命令名调用：

```bash
guardrailmap --help
```

也可以不用安装，直接把 `guardrailmap.py` 拷走用——它只依赖标准库。

## 为什么需要它

安全清单多靠人工维护；guardrailmap 从代码与提示词里提取实际生效的约束，与声明的清单做差集。

它遵守下面几条自己定的规矩：

1. **声明与现实要对得上**。写在文档里的约束和代码里真正生效的约束，经常已经是两份东西。
2. **只做差集**。不判断约束合不合理，只检查声明与现实对不对得上。
3. **冲突要标出来**。两条互斥的约束同时存在时，实际生效的是哪条，得让人去确认。

## 用法

```bash
python guardrailmap.py --declared guards.md --source app.py
python guardrailmap.py --declared guards.md --source app.py --json
```

加 `--json` 可以拿到机器可读的结果，便于接到流水线里。

## 已知局限

- 约束识别靠措辞特征，写得太隐晦的约束会漏掉。
- 冲突判定只在同一风险类别内做，跨类别的互斥不会报。
- 不评价约束本身合不合理，只做声明与实现的差集。

## 跑测试

```bash
python test_guardrailmap.py
```

测试用独立的断言与临时数据，不污染工作目录。

## 来源与参考

- Python 标准库文档：<https://docs.python.org/3/>
- GitHub 仓库：<https://github.com/oussam-zz/guardrailmap>

---

## 关于作者

oussam-zz 做安全约束的覆盖审计相关的问题。这个工具先替你回答一个具体问题，再谈别的。

- 个人主页：<https://oussam-zz.github.io>
- 仓库：<https://github.com/oussam-zz/guardrailmap>

## 许可

MIT，见 [LICENSE](LICENSE)。
