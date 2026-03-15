# ClawLens

ClawLens 是一款面向企业终端的 OpenClaw 安全检测工具，支持 Linux、macOS 和 Windows。

它用于快速识别 OpenClaw 安装情况、运行状态、危险配置与凭证权限风险，并输出 HTML / JSON 报告，便于人工排查和自动化接入。

## 安全能力

- 检测 OpenClaw 主目录、配置文件、工作区与会话目录
- 识别运行中的相关进程与系统服务
- 检查高风险配置，如 `shellAccess: true` 和 Gateway 监听 `0.0.0.0`
- 检查凭证目录及文件权限是否过宽

## 适配环境

- Linux `amd64` / `arm64`
- macOS `amd64` / `arm64`
- Windows `amd64`
- 单二进制运行，零外部依赖

## 安装方式

下载 GitHub Releases 中对应平台的二进制文件后直接运行，或从源码构建：

```bash
make build
./clawlens
```

也可以直接执行：

```bash
go run ./cmd/clawlens
```

## 操作指南

```bash
clawlens                       # 扫描并打开 HTML 报告
clawlens -f json              # 输出 JSON 报告
clawlens -o report.html       # 指定输出路径
clawlens --no-open            # 不自动打开浏览器
clawlens --openclaw-home /path
clawlens -q                   # 静默模式，仅返回退出码
clawlens -v                   # 打印版本号
```

退出码：

- `0` Clean
- `1` Info
- `2` Warning
- `3` Critical

## 开源说明

- License: Apache-2.0
- 安全问题披露见 [SECURITY.md](SECURITY.md)
- 贡献说明见 [CONTRIBUTING.md](CONTRIBUTING.md)
