-- Copyright (C) K8sCat<k8scat@gmail.com>
-- https://open.work.weixin.qq.com/api/doc/90000/90135/90664

local json = require("cjson")
local jwt = require("resty.jwt")
local http = require("resty.http")
local ngx = require("ngx")

local ok, new_tab = pcall(require, "table.new")
if not ok or type(new_tab) ~= "function" then
    new_tab = function (narr, nrec) return {} end
end

local jwt_header_alg = "HS256"

local _M = new_tab(0, 30)

_M._VERSION = "0.0.3"

_M.corp_id = ""
_M.app_agent_id = ""
_M.app_secret = ""
_M.callback_uri = "/weauth_callback"
_M.app_domain = ""

_M.jwt_secret = ""
_M.jwt_expire = 28800 -- 8小时

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
    for i=1, #tab do
        if tab[i] == val then
            return true
        end
    end
    return false
end

function _M:get_access_token()
    local url = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
    local query = {
        corpid = self.corp_id,
        corpsecret = self.app_secret
    }
    local res, err = http_get(url, query)
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
    return data["access_token"]
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

function _M:clear_token()
    ngx.header["Set-Cookie"] = self.cookie_key .. "=; expires=Thu, 01 Jan 1970 00:00:00 GMT"
end

function _M:logout()
    self:clear_token()
    return ngx.redirect(self.logout_redirect)
end

function _M:get_user_id(access_token, code)
    local url = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo"
    local query = {
        access_token = access_token,
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

function _M:get_user(access_token, user_id)
    local url = "https://qyapi.weixin.qq.com/cgi-bin/user/get"
    local query = {
        access_token = access_token,
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
    local user_id = user["userid"]
    if not user_id or user_id == "" then
        return nil, "invalid userid"
    end
    local department_ids = user["department"]
    if not department_ids or type(department_ids) ~= "table" then
        return nil, "invalid department"
    end

    return jwt:sign(
        self.jwt_secret,
        {
            header = {
                typ = "JWT",
                alg = jwt_header_alg,
                exp = ngx.time() + self.jwt_expire
            },
            payload = {
                userid = user_id,
                department = json.encode(department_ids)
            }
        }
    )
end

function _M:check_user_access(user)
    if type(self.department_whitelist) ~= "table" then
        ngx.log(ngx.ERR, "department_whitelist is not a table")
        return false
    end
    if #self.department_whitelist == 0 then
        return true
    end

    local department_ids = user["department"]
    if not department_ids or department_ids == "" then
        return false
    end
    if type(department_ids) ~= "table" then
        department_ids = json.decode(department_ids)
    end
    for i=1, #department_ids do
        if has_value(self.department_whitelist, department_ids[i]) then
            return true
        end
    end
    return false
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
    if not access_token then
        ngx.log(ngx.ERR, "get access_token failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local user_id, err = self:get_user_id(access_token, code)
    if not user_id then
        ngx.log(ngx.ERR, "get user id failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.log(ngx.ERR, "user id: ", user_id)

    local user, err = self:get_user(access_token, user_id)
    if not user then
        ngx.log(ngx.ERR, "get user failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.log(ngx.ERR, "login user: ", json.encode(user))

    if not self:check_user_access(user) then
        ngx.log(ngx.ERR, "user access not permitted")
        return self:sso()
    end

    local token, err = self:sign_token(user)
    if not token then
        ngx.log(ngx.ERR, "sign token failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.header["Set-Cookie"] = self.cookie_key .. "=" .. token

    local redirect_url = request_args["state"]
    if not redirect_url or redirect_url == "" then
        redirect_url = "/"
    end
    return ngx.redirect(redirect_url)
end

function _M:auth()
    local request_uri = ngx.var.uri
    ngx.log(ngx.ERR, "request uri: ", request_uri)

    if has_value(self.uri_whitelist, request_uri) then
        ngx.log(ngx.ERR, "uri in whitelist: ", request_uri)
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
        if self:check_user_access(payload) then
            return
        end

        ngx.log(ngx.ERR, "user access not permitted")
        self:clear_token()
        return self:sso()
    end
    ngx.log(ngx.ERR, "verify token failed: ", err)

    if request_uri ~= self.callback_uri then
        return self:sso()
    end
    return self:sso_callback()
end

return _M
