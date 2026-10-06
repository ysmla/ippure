# IPPure - IP纯净度检测平台

专业IP纯净度检测网站，支持IP检测、出口检测、VPN溯源、浏览器指纹检测等功能。

## 项目归属

- **灵感来源**：[https://ippure.com/](https://ippure.com/)
- **原项目仓库**：[https://github.com/ygyang2023/ippure](https://github.com/ygyang2023/ippure)

## 账户系统集成

本项目已集成 **cloud-mail** 账户系统，提供用户认证服务：

- **cloud-mail 项目**：[https://github.com/maillab/cloud-mail](https://github.com/maillab/cloud-mail)
- **认证服务**：通过 cloud-mail 的 API 进行用户身份验证
- **注册地址**：[https://mail.ygyang.uk/login](https://mail.ygyang.uk/login)

### 集成特性

- ✅ 页面内直接登录，无需跳转
- ✅ 支持注册跳转至 cloud-mail 注册页面
- ✅ 使用 cloud-mail API 进行身份验证
- ✅ 聊天记录存储在 Cloudflare KV 中
- ✅ 聊天记录自动清理（保留最近7天）

## 功能特性

- **IP检测** - 多数据源验证，获取准确IP定位信息
- **IP出口检测** - 全面检测IP出口分布，在地图上显示出口IP分布
- **VPN溯源** - 检测VPN泄露风险，包含WebRTC、DNS检测
- **WebRTC泄露检测** - 检测WebRTC是否暴露真实IP
- **DNS泄露检测** - 检测DNS解析是否泄露隐私
- **浏览器指纹检测** - 检测浏览器指纹信息
- **聊天系统** - 基于 cloud-mail 账户的实时聊天功能（原网上邻居）
- **IP信息卡片** - 生成访客IP信息卡片图片
- **风险评估可视化** - 水平条形图展示IPPure和Cloudflare系数
- **地理位置国旗显示** - 根据IP地址显示对应国家国旗
- **API接口** - 提供公开API供开发者使用

## 技术栈

- Cloudflare Workers
- TypeScript
- Wrangler CLI
- Cloudflare KV（聊天记录存储）
- cloud-mail（用户认证）

## 部署方式

### GitHub集成部署

1. **连接Cloudflare Workers**
   - 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
   - 进入 **Workers & Pages**
   - 点击 **Create application** → **Create Worker**
   - 选择 **Deploy from GitHub**
   - 授权GitHub仓库访问
   - 选择仓库和分支（main）
   - 配置构建命令：`npm run build`
   - 设置入口文件：`src/index.ts`

2. **配置 KV 命名空间绑定**
   - 在 Cloudflare Dashboard 中创建 KV 命名空间 `IPPURE_CHATS`
   - 在 Worker 设置中绑定 KV 命名空间：
     - Variable name: `IPPURE_CHATS`
     - KV namespace: 选择创建的 `IPPURE_CHATS` 命名空间

3. **配置自定义域名（可选）**
   - 在 Workers & Pages 设置中点击 **Triggers**
   - 点击 **Add Custom Domain**
   - 输入您的域名并验证

### 方式二：Wrangler CLI 部署

```bash
# 安装依赖
npm install

# 创建 KV 命名空间
npx wrangler kv:namespace create IPPURE_CHATS

# 更新 wrangler.toml 中的 KV ID

# 登录Cloudflare
npx wrangler login

# 部署
npm run deploy
```

## 本地开发

```bash
# 安装依赖
npm install

# 创建本地 KV 命名空间（开发环境）
npx wrangler kv:namespace create IPPURE_CHATS --preview

# 本地开发
npm run dev
```

访问 `http://localhost:8787` 查看效果。

## API接口

### 获取IP信息

```bash
curl -L https://your-domain.com/v1/info
```

返回示例：

```json
{
  "ip": "104.28.123.123",
  "asn": 13335,
  "asOrganization": "Cloudflare, Inc.",
  "country": "中国",
  "countryCode": "CN",
  "region": "湖南省",
  "regionCode": "HN",
  "city": "长沙市",
  "timezone": "Asia/Shanghai",
  "longitude": "-118.24368",
  "latitude": "34.05223",
  "postalCode": "410000",
  "fraudScore": 75,
  "ippureCoefficient": 47,
  "cloudflareCoefficient": 32,
  "isResidential": false,
  "isBroadcast": false,
  "isDataCenter": true,
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}
```

### 获取IP信息卡片

```bash
curl -L https://your-domain.com/v1/card
```

### 聊天 API

#### 登录

```bash
curl -X GET "https://your-domain.com/v1/chat/login?email=user@example.com&password=yourpassword"
```

#### 发送消息

```bash
curl -X POST "https://your-domain.com/v1/chat/send" \
  -H "Content-Type: application/json" \
  -H "X-User-Id: user123" \
  -d '{"content":"Hello"}'
```

#### 获取消息

```bash
curl -H "X-User-Id: user123" https://your-domain.com/v1/chat/messages
```

## 风险系数说明

### IPPure系数

- **0-25%**：安全
- **26-50%**：轻度风险
- **51-70%**：中度风险
- **71-100%**：高度风险

### Cloudflare系数

基于Cloudflare智能评估的综合风险评分。

## 页面路由

| 页面 | 路由 |
|------|------|
| IP检测（首页） | `/` |
| IP出口检测 | `/IP-Outbound-Detect.html` |
| VPN溯源 | `/IP-leak-Detect.html` |
| WebRTC泄露检测 | `/Browser-WebRTC-Leak-Detect.html` |
| DNS泄露检测 | `/DNS-Leak-Detect.html` |
| 指纹检测 | `/fingerprint.html` |
| 聊天系统 | `/neighbors.html` |
| IP信息卡片 | `/MyIP-Info-Card.html` |
| API接口 | `/MyIP-Info-API.html` |
| 关于本站 | `/about.html` |
| 常见问题 | `/faq.html` |
| 数据纠正记录 | `/correction.html` |
| 功能更新日志 | `/changelog.html` |
| 联系方式 | `/contact.html` |
| 使用条款与隐私 | `/terms-privacy.html` |

## 项目结构

```
ippure/
├── src/
│   └── index.ts          # Cloudflare Worker 主文件
├── public/               # 静态资源目录
├── package.json          # 项目依赖配置
├── tsconfig.json         # TypeScript 配置
├── wrangler.toml         # Cloudflare Workers 配置
├── README.md             # 项目说明文档
└── LICENSE               # MIT 许可证
```

## cloud-mail 集成配置

本项目直接连接 cloud-mail 的 D1 数据库进行用户身份验证。

### 数据库配置

| 配置项 | 值 | 说明 |
|--------|-----|------|
| **D1 Database** | `cnmailcn` | cloud-mail 用户数据库 |
| **D1 Binding** | `db` | 代码中引用的变量名 |
| **D1 Database ID** | `9e755ce9-d779-4afe-af61-20996946cf16` | D1 数据库唯一标识符 |
| **KV Namespace** | `IPPURE_CHATS` | 聊天记录存储 |

### 登录流程

1. 用户在 `/neighbors.html` 页面输入邮箱和密码
2. 前端调用 `/v1/chat/login` 接口
3. Worker 直接查询 cloud-mail D1 数据库验证用户
4. 验证成功后返回用户信息，存储到 localStorage
5. 用户进入聊天界面

### 用户表结构

cloud-mail D1 数据库中的 `user` 表结构：

| 字段 | 类型 | 说明 |
|------|------|------|
| `user_id` | INTEGER | 用户ID（主键） |
| `email` | TEXT | 用户邮箱 |
| `password` | TEXT | 密码哈希（SHA-256） |
| `salt` | TEXT | 盐值 |
| `status` | INTEGER | 账户状态（0=正常，1=禁用） |
| `is_del` | INTEGER | 删除标记（0=未删除） |

### 数据存储

- **用户认证**：cloud-mail D1 数据库（`user` 表）
- **聊天记录**：Cloudflare KV，Key 格式为 `{userId}:{messageId}`
- **数据保留**：聊天记录仅保留最近7天
- **自动清理**：每次发送消息时自动清理过期记录

## 故障排除

### 常见问题

1. **KV 绑定失败**
   - 确保 KV 命名空间名称为 `IPPURE_CHATS`
   - 检查 wrangler.toml 中的 ID 是否正确
   - 在 Dashboard 中重新绑定

2. **登录失败**
   - 确保 cloud-mail 服务正常运行
   - 检查邮箱和密码是否正确
   - 确认网络连接正常

3. **聊天记录不显示**
   - 检查 KV 命名空间是否正确绑定
   - 确认用户 ID 是否正确传递
   - 检查浏览器控制台是否有错误

4. **D1 数据库绑定错误**
   - **错误信息**："添加绑定失败：发生未知错误"
   - **API 错误**：POST `/api/v4/accounts/.../workers/scripts/ippure/versions` 返回 403
   
   **解决方法**：
   
   1. **权限问题**：
      - 确保有访问 cloud-mail D1 数据库的权限
      - 检查账户权限级别
      - 确认在同一个 Cloudflare 账户内
   
   2. **直接在 Dashboard 绑定**：
      - 访问：https://dash.cloudflare.com/[你的账户ID]/workers/services/view/ippure/production/bindings
      - 在 "D1 Database Bindings" 部分点击 "Add binding"
      - 变量名填：`db`
      - 选择数据库：`cnmailcn`（或你实际的数据库名称）
      - 点击 "Save and Deploy"
   
   3. **使用 wrangler CLI 绑定**：
      ```bash
      # 先列出可访问的D1数据库
      npx wrangler d1 list
      
      # 确认数据库ID和名称
      # 然后在 wrangler.toml 中配置（可选）
      ```
   
   4. **共享权限**：
      - 如果数据库在另一个账户，需要请求共享访问
      - 使用 Cloudflare Resource Access 授予权限
      - 或者将两个项目放在同一个账户内
   
   5. **验证绑定**：
      部署成功后可以测试登录功能验证数据库连接是否正常

## 许可证

MIT License