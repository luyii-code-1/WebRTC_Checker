# webrtc-ip-leak-checker

WebRTC IP 泄露检测工具，用于访问 Claude / 其他网站前自检浏览器和代理环境是否可能因 WebRTC 暴露非预期网络出口信息。

本项目仅检测，不跳转，不追踪，不存储。它不会把 WebRTC `srflx` 地址描述成真实家庭宽带 IP；`srflx` 只代表 STUN 看到的网络出口。检测结果受浏览器、VPN、代理、系统网络设置影响，仅供参考。

## 功能列表

- HTTP 出口 IP 检测。
- Cloudflare `request.cf` 信息展示。
- WebRTC ICE candidate 检测。
- `host` / `srflx` / `relay` / `prflx` 分类。
- IPv4 / IPv6 / 私网 / 公网 / mDNS / relay 展示。
- HTTP IP 与 WebRTC `srflx` 公网 IP 对比。
- 风险等级判断。
- JSON 报告复制。

## 隐私说明

- 默认不保存日志。
- WebRTC candidate 默认只在浏览器本地解析。
- `/api/ip` 只返回当前访问请求的出口信息。
- 不需要摄像头/麦克风权限。
- 不设置 Cookie。
- 不使用 LocalStorage。
- 不使用数据库。
- 不使用 KV、D1、R2。
- 不使用第三方 CDN。

## 本地运行方式

静态页面可以直接打开 `index.html`。但 `/api/ip` 需要 Cloudflare Pages Functions 环境，推荐使用 Wrangler 本地预览。

```bash
npm install -g wrangler
wrangler pages dev .
```

本地预览后访问：

```text
http://localhost:8788/
http://localhost:8788/api/ip
```

## GitHub 初始化方式

```bash
git init
git add .
git commit -m "Initial WebRTC leak checker"
git branch -M main
git remote add origin https://github.com/<your-name>/webrtc-ip-leak-checker.git
git push -u origin main
```

## Cloudflare Pages 部署方式

1. 打开 Cloudflare Dashboard → Workers & Pages → Create application → Pages。
2. 选择 Connect to Git。
3. 选择 GitHub 仓库。
4. Framework preset 选择 None / Static HTML。
5. Build command 留空。
6. Build output directory 填 `/` 或留空，按 Cloudflare 当前 UI 支持填写。
7. Functions 目录保持在仓库根目录 `/functions`。
8. 部署完成后访问：

```text
https://<project>.pages.dev/
https://<project>.pages.dev/api/ip
```

## 注意事项

- 检测结果受浏览器、VPN、代理、系统网络设置影响。
- WebRTC `srflx` 不一定等于真实家庭宽带 IP。
- 现代浏览器可能使用 mDNS 隐藏本地 IP。
- 如果 WebRTC 公网 IP 与 HTTP IP 不一致，才提示高风险。
- 这个工具不能保证发现所有泄露场景。
- 本项目代码不写入应用日志、不保存检测结果；Cloudflare 平台自身的边缘访问日志不由本项目控制。

## 项目结构

```text
webrtc-ip-leak-checker/
├─ index.html
├─ style.css
├─ app.js
├─ functions/
│  └─ api/
│     └─ ip.js
├─ README.md
├─ LICENSE
├─ .gitignore
└─ wrangler.toml
```
