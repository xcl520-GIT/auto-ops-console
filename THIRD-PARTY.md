# 第三方组件

> ★ 这一节**原来挂在 `LICENSE` 正文后面** —— 结果 GitHub 的许可证识别把整个 `LICENSE`
> 判成「**Other**」而不是「**MIT**」（多出来的文字打断了它的模式匹配）。
> ⇒ 拆出来：`LICENSE` 保持 **MIT 正文逐字原样**（这样 GitHub 能正确显示 `MIT` 徽标），
> 第三方声明挪到这里。**两边的文字都没有改**，只是换了位置。

本仓库随源码自带（`repo/vendor/`）的第三方组件：

- `repo/vendor/pyyaml` — **PyYAML**，MIT License。
  全文见 `repo/vendor/pyyaml-6.0.3.dist-info/licenses/LICENSE`。

★ 除它以外，运行期**不引入任何第三方包**：后端只用 Python 标准库，前端是原生
HTML/CSS/JS（无构建链、无 `node_modules`），存储用标准库的 `sqlite3`。
