package = "lua-resty-weauth"
version = "0.0.3-0"
source = {
   url = "https://github.com/k8scat/lua-resty-weauth",
   tag = "v0.0.3"
}
description = {
   summary = "适用于 OpenResty / ngx_lua 的基于企业微信组织架构的登录认证",
   homepage = "https://github.com/k8scat/lua-resty-weauth",
   license = "MIT",
   maintainer = "K8sCat <k8scat@gmail.com>"
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      ["resty.weauth"] = "lib/resty/weauth.lua"
   }
}