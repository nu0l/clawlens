# ClawLens 使用指南

## 安装

从 [GitHub Releases](https://github.com/clawlens/clawlens/releases) 下载对应平台的二进制文件，或从源码构建：

```bash
make build
./clawlens
```

## 命令行选项

```bash
clawlens                          # 扫描并打开 HTML 报告
clawlens -f json                  # 输出 JSON 报告
clawlens -o report.html           # 指定输出路径
clawlens --no-open                # 不自动打开浏览器
clawlens --openclaw-home /path    # 指定 OpenClaw 主目录
clawlens --targets 192.168.1.0/24 # 扫描指定 IP/网段中的 OpenClaw 网关与风险
clawlens -q                       # 静默模式，仅返回退出码
clawlens -v                       # 打印版本号
```

终端输出默认带彩色高亮，设置环境变量 `NO_COLOR=1` 可关闭。

## 退出码

| 退出码 | 含义   |
|--------|--------|
| `0`    | 安全   |
| `1`    | 提示   |
| `2`    | 警告   |
| `3`    | 严重   |

退出码反映本次扫描中最高风险等级，适合在 CI/CD 或自动化脚本中使用。

## 无桌面环境

在无图形界面的服务器上运行时，ClawLens 会自动跳过浏览器打开步骤。可将生成的报告文件复制到有浏览器的机器上查看，或使用 `-f json` 输出 JSON 格式供程序消费。

## 支持平台

| 操作系统 | 架构               |
|----------|-------------------|
| Linux    | `amd64` / `arm64` |
| macOS    | `amd64` / `arm64` |
| Windows  | `amd64`           |

单二进制运行，零外部依赖（`CGO_ENABLED=0`）。
