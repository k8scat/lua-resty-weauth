--- Simple locking module using redis and ngx_lua
-- @module resty.redis.lock

local ngx = require 'ngx'
local setmetatable = setmetatable

-- I disdain module(), but that's the way the lua-resty stuff seems to always be done
-- so why fight it
module(...)

_VERSION = '0.1.2'

local mt = { __index = _M }

local scripts = {
    touch = {
        script = [[
local val = redis.call('get', KEYS[1])
if not val then
    return 0
end
if val == ARGV[1] then
    redis.call('expire', KEYS[1], ARGV[2])
    return 1
else
    return 0
end
        ]],
        sha1 = nil
    },
    unlock = {
        script = [[
local val = redis.call('get', KEYS[1])
if not val then
    return 0
end
if val == ARGV[1] then
    redis.call('del', KEYS[1])
    return 1
else
    return 0
end
        ]],
        sha1 = nil
    },
    lock = {
        script = [[
local val = redis.call('setnx', KEYS[1], ARGV[1])
if val == 0 then
    return 0
end
redis.call('expire', KEYS[1], ARGV[2])
return 1
        ]],
        sha1 = nil
    }
}

local function call_script(self, script_name, ...)
    local redis = self.redis
    local script = scripts[script_name]
    if not script then
        return nil, "invalid script"
    end

    local sha1 = script.sha1
    
    if not sha1 then
        -- we could do the sha ourselves, but just be 100% sure that
        -- it matches redis by letting redis tell us. Also, this will work
        -- when LuaJit is not availible
        local ans, err = redis:script("LOAD", script.script)
        if not ans then
            return nil, err
        end
        sha1 = ans
        script.sha1 = sha1
    end

    local ans, err = redis:evalsha(sha1, 1, self.key, self.id, ...)
    if not ans then
        return nil, err
    end
    return ans
end

--- create a new redis lock.
-- @tparam resty.redis redis a resty.redis object
-- @tparam string key key to use for locking. The actual redis key will be this string prepended with "LOCK:"
-- @tparam number ttl expiry time for the lock. default is 60 seconds
-- @treturn resty.redis.lock a lock object
function new(redis, key, ttl)
    return setmetatable( { redis = redis, key = "LOCK:" .. key, ttl = ttl or 60 }, mt)
end

-- try to obtain the lock
-- @tparam resty.redis.lock self
-- @treturn boolean lock results. Technically it returns a string on success and a nil on failure, but should be treated as a boolean
-- @treturn string error, if applicable
function try_lock(self)
    self.id = ngx.now() + self.ttl + 1

    local ans, err = call_script(self, "lock", self.ttl)
    if 1 ~= ans then
        self.id = nil
    end

    return self.id
end

--- try to obtain the lock. Retry until lock is obtained or after a certain number of retries
-- @tparam resty.redis.lock self
-- @tparam number retries how many time to attempt to obtain the lock. default: 100
-- @tparam number sleep how long to sleep between retries. default: 0.010 (10ms). With the defaults, the lock will be retried for 10 seconds
-- @treturn boolean lock results. @see try_lock
-- @treturn string error, if applicable
function lock(self, retries, sleep)
    retries = retries or 100
    if retries < 1 then retries = 1 end
        sleep = sleep or 0.010
    local locked, err = nil
    repeat
        locked, err = self:try_lock()
        retries = retries - 1
        ngx.sleep(sleep)
    until locked or retries == 0
    return locked, err
end

--- "touch" the lock. If the lock is held, extend the expire time
-- @tparam resty.redis.lock self
-- @tparam number ttl how long to extend the lock for. default: value of ttl passed to `new`
-- @treturn boolean success
-- @treturn string error, if applicable
function touch(self, ttl)
    ttl = ttl or self.ttl
    if not self.id then
        return nil, "not locked"
    end

    local ans, err = call_script(self, "touch", ttl)
    if not ans then
        return nil, err
    end
    return (ans == 1)
end

--- unock the lock
-- @tparam resty.redis.lock self
-- @treturn boolean if lock was successfully unlocked
-- @treturn string error, if applicable
function unlock(self)
    if not self.id then
        return nil, "not locked"
    end
    local ans, err = call_script(self, "unlock")
    if not ans then
        return nil, err
    end
    self.id = nil
    
    return (ans == 1)
end

local class_mt = {
    -- to prevent use of casual module global variables
    __newindex = function (table, key, val)
        error('attempt to write to undeclared variable "' .. key .. '"')
    end
}

setmetatable(_M, class_mt)
