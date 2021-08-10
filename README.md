# lua-resty-weauth

使用 ngx_lua 的基于企业微信组织架构的登录认证

## 使用

### 下载

```bash
cd /path/to
git clone git@github.com:ledgetech/lua-resty-http.git
git clone git@github.com:SkyLothar/lua-resty-jwt.git
git clone git@github.com:openresty/lua-resty-redis.git
git clone git@github.com:bakins/lua-resty-redis-lock.git
git clone git@github.com:k8scat/lua-resty-weauth.git
```

### 配置

```conf
lua_package_path "/path/to/lua-resty-weauth/lib/?.lua;/path/to/lua-resty-jwt/lib/?.lua;/path/to/lua-resty-http/lib/?.lua;/path/to/lua-resty-redis/lib/?.lua;/path/to/lua-resty-redis-lock/lib/?.lua;;";

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

        weauth.ip_blacklist = {}
        weauth.uri_whitelist = {"/"}
        weauth.department_whitelist = {1, 2}

        weauth:auth()
    }
}
```

## 依赖模块

- [lua-resty-http](https://github.com/ledgetech/lua-resty-http)
- [lua-resty-jwt](https://github.com/SkyLothar/lua-resty-jwt)
- [lua-resty-redis](https://github.com/openresty/lua-resty-redis)
- [lua-resty-redis-lock](https://github.com/bakins/lua-resty-redis-lock)
