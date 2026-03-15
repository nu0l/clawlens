# Contributing

感谢提交改进。

## Development Setup

```bash
go test ./...
make build
```

项目只依赖 Go 标准库，默认不需要额外依赖安装。

## Before Opening a Pull Request

- 运行 `gofmt -w .`
- 运行 `go test ./...`
- 如果修改了 CLI、输出格式或发布行为，请同步更新 [README.md](README.md)
- 保持提交范围聚焦，避免把构建产物或扫描报告一起提交

## Scope Guidelines

欢迎以下类型的改动：

- 新的平台检测能力
- 更准确的 OpenClaw 风险识别
- 报告输出改进
- 测试覆盖补全
- 文档和发布流程修正

不建议在同一个 PR 中混合大量重构和功能改动。

## Versioning And Releases

- 日常开发通过 Pull Request 合并
- 发布通过 Git tag 触发 GitHub Actions Release workflow
- 如果仓库最终 URL 不是 `github.com/clawlens/clawlens`，请先同步调整 [go.mod](go.mod)
