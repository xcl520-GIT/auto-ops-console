# 反例配方样例（T7·S5 · 规范 §12.21）

★ 这三份是**故意写错的配方**，用途只有两个：

1. **给人看**："写坏了会得到什么反馈" —— 每份都标了「期望被点名的那句话」；
2. **给自检看**："装载期校验真的会拒、而且拒的理由对不对"（自检断言 ㉖ 会逐份核）。

| 文件 | 故意错在哪 | 期望装载期点名 |
|---|---|---|
| `bad-command.yaml` | **把命令写进了配方**（`run: [systemctl, restart, nginx]`） | `run`（宪法①：配方只声明"要什么"） |
| `bad-uninstall.yaml` | **卸载段不完整**（只写了 `stop`，没有 `disable` / 删配置 / 卸包） | `uninstall` 里缺的那些键 |
| `bad-ref.yaml` | **引用了不存在的东西**（动作 `myapp.start`；`absent` 用了 `net.port`；`responds` 用了 `net.ping`） | `myapp.start` 不存在 · `net.port` 不是存在性来源 · `net.ping` 不是探活动作 |

★ 怎么用它们：

```powershell
# 看这三份被拒的理由（**不会**碰目标机）
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from app.yamlload import load_yaml; from app.recipe import parse_recipe; from app.catalog import load_actions; from app.config import load as lc; cfg=lc('.'); acts=load_actions(cfg.paths.actions)
for p in sorted(Path('var/lab/recipes-bad').glob('*.yaml')):
    r, errs = parse_recipe(load_yaml(p, what='配方'), p, acts)
    print(p.name, '→', ' | '.join(errs) or '（竟然通过了！）')"
```

★ 或者更省事：把某一份**复制**到 `catalog/recipes/`（文件名与 id 一致），然后点界面上的
「重新装载配方」—— 你会看到它**明确说出是哪一份、错在哪个键**，而**其余配方照常可用**（规范 §12.17）。
★ 看完记得删掉：`Remove-Item catalog\recipes\bad-*.yaml`。
