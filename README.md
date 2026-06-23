# ProxyPress — 订阅转换器

基于 [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) 规则集的在线订阅转换工具，支持 proxy-providers / rule-providers 动态拉取模式。

## 功能

- 🔀 订阅链接 → Clash / Surge / Quantumult 等客户端配置
- 📰 报纸风格 Web UI
- ⚡ proxy-providers + rule-providers 双动态模式（配置瘦身 44x）
- 📥 一键下载配置文件
- 🐳 Docker 一键部署

## 快速开始

```bash
git clone https://github.com/<your>/<repo>.git
cd <repo>
make up        # 启动所有服务
```

打开 http://localhost:58080

## 项目结构

```
├── docker-compose.yml    # 3 服务：subconverter + sub-smart + sub-web
├── smart/                # 后端转换服务（Python）
├── sub-web/              # 前端 UI（Vue.js，报纸风格）
├── Clash/ Acl/ Tool/     # ACL4SSR 规则文件
└── .github/workflows/    # CI/CD（GitHub Pages 自动部署）
```

## 原作者 & 致谢

- **ACL4SSR** — 规则集维护者，本项目基于其 [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) 构建
- **subconverter** — [tindy2013/subconverter](https://github.com/tindy2013/subconverter) 订阅转换引擎
- **sub-web** — [CareyWang/sub-web](https://github.com/CareyWang/sub-web) 前端基础

## 许可证

规则文件 (Clash/, Acl/, Tool/) 沿用 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)

本项目新增代码 (smart/, sub-web/, scripts/) 采用 [MIT](LICENSE-MIT)
