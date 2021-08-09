-- Copyright (C) K8sCat<k8scat@gmail.com>
-- https://open.work.weixin.qq.com/api/doc/90000/90135/90664

local json = require("cjson")
local jwt = require("resty.jwt")
local redis = require("resty.redis")
local http = require("resty.http")
local redis_lock = require("resty.redis_lock")
local ngx = require("ngx")

local ok, new_tab = pcall(require, "table.new")
if not ok or type(new_tab) ~= "function" then
    new_tab = function (narr, nrec) return {} end
end

local jwt_header_iss = "weauth"
local jwt_header_alg = "HS256"

local redis_key_access_token = "weauth_access_token"

local _M = new_tab(0, 30)

_M._VERSION = "0.0.1"

_M.corp_id = ""
_M.app_agent_id = ""
_M.app_secret = ""
_M.callback_uri = "/weauth_callback"
_M.app_domain = ""

_M.access_token = ""

_M.jwt_secret = ""
_M.jwt_expire = 86400

_M.redis_host = "127.0.0.1"
_M.redis_port = 6379
_M.redis_sock = ""
_M.redis_pass = ""
_M.redis_db = 0

_M.logout_uri = "/weauth_logout"
_M.logout_redirect = "/"

_M.cookie_key = "weauth_token"

_M.ip_blacklist = {}
_M.uri_whitelist = {}
_M.department_whitelist = {}

local function http_get(url, query)
    local request = http.new()
    request:set_timeout(10000)
    return request:request_uri(url, {
        method = "GET",
        query = query,
        ssl_verify = false
    })
end

local function has_value(tab, val)
    for i, v in ipairs(tab) do
        if v == val then
            return true
        end
    end
    return false
end

function _M:get_access_token()
    local red, err = self:redis_connect()
    if not red then
        return nil, err
    end
    local res, err = red:get(redis_key_access_token)
    if res and res ~= ngx.null then
        return res
    end
    ngx.log(ngx.ERR, "failed to get token from redis: ", err)

    local access_token = nil
    local l = redis_lock.new(red, redis_key_access_token)
    if l:lock() then
        ngx.log(ngx.ERR, "redis locked")
        res, err = red:get(redis_key_access_token)
        if res and res ~= ngx.null then
            return res
        end
        ngx.log(ngx.ERR, "still failed to get token from redis: ", err)

        local url = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
        local query = {
            corpid = self.corp_id,
            corpsecret = self.app_secret
        }
        res, err = http_get(url, query)
        if not res then
            return nil, err
        end
        if res.status ~= 200 then
            return nil, res.body
        end
        local data = json.decode(res.body)
        if data["errcode"] ~= 0 then
            return nil, res.body
        end

        access_token = data["access_token"]
        local expires_in = data["expires_in"]
        local ok, err = red:setex(redis_key_access_token, expires_in, access_token)
        if not ok then
            ngx.log(ngx.ERR, "failed to set access token into redis: ", err)
        end
	    l:unlock()
        ngx.log(ngx.ERR, "redis unlocked")
    end
    return access_token
end

function _M:sso()
    local callback_url = ngx.var.scheme .. "://" .. self.app_domain .. self.callback_uri
    local redirect_url = ngx.var.scheme .. "://" .. self.app_domain .. ngx.var.request_uri
    local args = ngx.encode_args({
        appid = self.corp_id,
        agentid = self.app_agent_id,
        redirect_uri = callback_url,
        state = redirect_url
    })
    return ngx.redirect("https://open.work.weixin.qq.com/wwopen/sso/qrConnect?" .. args)
end

function _M:logout()
    ngx.header["Set-Cookie"] = self.cookie_key .. "=; expires=Thu, 01 Jan 1970 00:00:00 GMT"
    return ngx.redirect(self.logout_redirect)
end

function _M:get_user_id(code)
    local url = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo"
    local query = {
        access_token = self.access_token,
        code = code,
    }
    local res, err = http_get(url, query)
    if not res then
        return nil, err
    end
    if res.status ~= 200 then
        return nil, res.body
    end
    local user = json.decode(res.body)
    if user["errcode"] ~= 0 then
        return nil, res.body
    end
    return user["UserId"]
end

function _M:get_user(user_id)
    local url = "https://qyapi.weixin.qq.com/cgi-bin/user/get"
    local query = {
        access_token = self.access_token,
        userid = user_id
    }
    ngx.log(ngx.ERR, "get user query: ", json.encode(query))
    local res, err = http_get(url, query)
    if not res then
        return nil, err
    end
    if res.status ~= 200 then
        return nil, res.body
    end
    local user = json.decode(res.body)
    if user["errcode"] ~= 0 then
        return nil, res.body
    end
    return user
end

function _M:verify_token()
    local token = ngx.var.cookie_weauth_token
    if not token then
        return nil, "token not found"
    end

    local result = jwt:verify(self.jwt_secret, token)
    ngx.log(ngx.ERR, "jwt_obj: ", json.encode(result))
    if result["valid"] then
        local payload = result["payload"]
        if payload["userid"] and payload["department"] then
            return payload
        end
        return nil, "invalid token: " .. json.encode(result)
    end
    return nil, "invalid token: " .. json.encode(result)
end

function _M:sign_token(user)
    local now = ngx.time()
    return jwt:sign(
        self.jwt_secret,
        {
            header = {
                typ = "JWT",
                alg = jwt_header_alg,
                exp = now + self.jwt_expire,
                iss = jwt_header_iss,
                iat = now
            },
            payload = {
                userid = user["userid"],
                department = json.encode(user["department"])
            }
        }
    )
end

function _M:validate_user(payload, redirect_url)
    local user, err = nil, nil
    local departments = payload["department"]
    if payload["department"] then
        departments = json.decode(payload["department"])
        payload["department"] = departments
        user = payload
    else
        ngx.log(ngx.ERR, "login user id: ", user_id)
        if self.access_token == "" then
            local access_token, err = self:get_access_token()
            if not access_token then
                ngx.log(ngx.ERR, "get access token failed: ", err)
                return ngx.exit(ngx.HTTP_BAD_GATEWAY)
            end
            self.access_token = access_token
        end

        user, err = self:get_user(user_id)
        if not user then
            ngx.log(ngx.ERR, "get user failed: ", err)
            return ngx.exit(ngx.HTTP_NOT_FOUND)
        end
        ngx.log(ngx.ERR, "login user: ", json.encode(user))
        departments = user["department"]
    end

    for _, v in ipairs(departments) do
        if has_value(self.department_whitelist, v) then
            local token = self:sign_token(user)
            ngx.header["Set-Cookie"] = self.cookie_key .. "=" .. token
            if redirect_url then
                return ngx.redirect(redirect_url)
            end
            return
        end
    end
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

function _M:sso_callback()
    local request_args = ngx.req.get_uri_args()
    if not request_args then
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    local code = request_args["code"]
    if not code then
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    ngx.log(ngx.ERR, "sso code: ", code)

    local access_token, err = self:get_access_token()
    if not self.access_token then
        ngx.log(ngx.ERR, "get access token failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    self.access_token = access_token

    user_id, err = self:get_user_id(code)
    if not user_id then
        ngx.log(ngx.ERR, "get user id failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local redirect_url = request_args["state"]
    if redirect_url == "" then
        redirect_url = "/"
    end
    return self:validate_user({userid=user_id}, redirect_url)
end

function _M:auth()
    local request_uri = ngx.var.uri
    if has_value(self.uri_whitelist, request_uri) then
        return
    end

    local request_ip = ngx.var.remote_addr
    if has_value(self.ip_blacklist, request_ip) then
        ngx.log(ngx.ERR, "forbided ip: ", request_ip)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if request_uri == self.logout_uri then
        return self:logout()
    end

    local payload, err = self:verify_token()
    if payload then
        return self:validate_user(payload)
    end
    ngx.log(ngx.ERR, "verify token failed: ", err)

    ngx.log(ngx.ERR, "request uri: ", request_uri)
    if request_uri ~= self.callback_uri then
        return self:sso()
    end

    return self:sso_callback()
end

function _M:redis_connect()
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000) -- 1 sec

    local ok, err = nil, nil
    if self.redis_sock ~= "" then
        ok, err = red:connect(self.redis_sock)
    else
        ok, err = red:connect(self.redis_host, self.redis_port)
    end
    if not ok then
        return nil, "connect redis failed: " .. err
    end

    if self.redis_pass ~= "" then
        local res, err = red:auth(self.redis_pass)
        if not res then
            return nil, "authenticate redis failed: " .. err
        end
    end
    local result = red:select(self.redis_db)
    if result ~= "OK" then
        return nil, "select db failed: " .. result
    end
    return red
end

return _M
