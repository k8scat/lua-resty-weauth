# lua-resty-weauth

适用于 OpenResty/ngx_lua 的基于企业微信组织架构的登录认证

## 使用

### 下载

```bash
cd /path/to
git clone git@github.com:ledgetech/lua-resty-http.git
git clone git@github.com:SkyLothar/lua-resty-jwt.git
git clone git@github.com:k8scat/lua-resty-weauth.git
```

### 配置

```conf
lua_package_path "/path/to/lua-resty-weauth/lib/?.lua;/path/to/lua-resty-jwt/lib/?.lua;/path/to/lua-resty-http/lib/?.lua;;";

server {
    access_by_lua_block {
        local weauth = require "resty.weauth"
        weauth.corp_id = ""
        weauth.app_agent_id = ""
        weauth.app_secret = ""
        weauth.callback_uri = "/weauth_callback"
        weauth.logout_uri = "/weauth_logout"
        weauth.app_domain = "weauth.example.com"

        weauth.jwt_secret = "thisisjwtsecret"

        weauth.ip_blacklist = {"47.1.2.3"}
        weauth.uri_whitelist = {"/"}
        weauth.department_whitelist = {1, 2}

        weauth:auth()
    }
}
```

配置说明：

- `corp_id` 用于设置企业 ID
- `app_agent_id` 用于设置企业微信自建应用的 `AgentId`
- `app_secret` 用于设置企业微信自建应用的 `Secret`
- `callback_uri` 用于设置企业微信扫码登录后的回调地址（需设置企业微信授权登录中的授权回调域）
- `logout_uri` 用于设置登出地址
- `app_domain` 用于设置访问域名（需和业务服务的访问域名一致）
- `jwt_secret` 用于设置 JWT secret
- `ip_blacklist` 用于设置 IP 黑名单
- `uri_whitelist` 用于设置地址白名单，例如首页不需要登录认证
- `department_whitelist` 用于设置部门白名单（数字）

## 依赖模块

- [lua-resty-http](https://github.com/ledgetech/lua-resty-http)
- [lua-resty-jwt](https://github.com/SkyLothar/lua-resty-jwt)

## 相关项目

- [lua-resty-feishu-auth](https://github.com/k8scat/lua-resty-weauth) 适用于 OpenResty / ngx_lua 的基于[飞书](https://www.feishu.cn/)组织架构的登录认证

## 作者

K8sCat <k8scat@gmail.com>

## 开源协议

[MIT](./LICENSE)
