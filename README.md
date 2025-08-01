# CAS & OAuth2 认证服务器

基于Rust语言构建的轻量级认证服务，支持CAS及OAuth2协议集成，采用JWT进行安全令牌管理。

## 核心功能

✅ 实现完整的OAuth2认证流程
✅ 支持CAS协议的登录与验证
✅ 提供标准化的API接口：
  - `/oauth2/login`：OAuth2认证入口
  - `/cas/callback`：CAS回调处理
  - `/oauth2/token`：令牌交换接口
  - `/oauth2/userinfo`：用户信息获取

## 快速入门
```bash
# 克隆项目
git clone https://github.com/yourname/yourproject.git

# 安装依赖（需Rust工具链）
cargo build

# 配置初始化
cp config/config.example.toml config/config.toml

# 启动服务
cargo run
```

## 配置说明

核心配置项（`config/config.toml`）：
```toml
[server]
host = "127.0.0.1"
port = 3000
endpoint = "/api/v1"

[cas]
login_url = "https://cas.example.com/login"
validate_url = "https://cas.example.com/validate"
service_param = "service"

[jwt]
secret = "secure-secret-key"
expiration = 3600  # 1小时有效期
```

## 技术特点

- 使用 [`axum`](https://github.com/tokio-rs/axum) 框架实现高性能Web服务
- 通过 [`serde`](https://github.com/serde-rs/serde) 和 [`toml`](https://github.com/toml-lang/toml) 实现配置解析
- 采用 [`tokio`](https://github.com/tokio-rs/tokio) 进行异步网络处理
- 自定义错误类型覆盖各类认证异常场景
## 贡献指南

1. Fork项目并创建新分支
2. 实现具体功能模块
3. 提交PR并补充文档说明

## 项目状态

当前实现基础认证功能，后续计划：
- [ ] 增加JWT刷新机制
- [ ] 实现更完善的CAS协议支持
- [ ] 添加健康检查接口
