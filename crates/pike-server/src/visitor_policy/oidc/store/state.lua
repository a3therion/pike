-- All five keys share one hash tag. Every capacity check and consume is atomic.
-- Redis time decides expiry; writer clocks must be synchronized with Redis/IdP.
local pd, pe, pc, sd, se = unpack(KEYS)
local op, id, scope, value, expires = unpack(ARGV)
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local function drop_pending(key)
    local record = redis.call('HGET', pd, key)
    if record then
        local owner = cjson.decode(record).scope
        if redis.call('HINCRBY', pc, owner, -1) <= 0 then redis.call('HDEL', pc, owner) end
    end
    redis.call('HDEL', pd, key)
    redis.call('ZREM', pe, key)
end
local function prune(data, expiry, pending)
    for _, key in ipairs(redis.call('ZRANGEBYSCORE', expiry, '-inf', now)) do
        if pending then drop_pending(key)
        else redis.call('HDEL', data, key); redis.call('ZREM', expiry, key) end
    end
end
local function remaining(key, owner)
    if redis.call('HGET', sd, key) ~= owner then return '0' end
    local deadline = tonumber(redis.call('ZSCORE', se, key) or '0')
    return tostring(math.max(0, deadline - now))
end
if op == 'begin' then
    prune(pd, pe, true)
    if tonumber(expires) <= now or redis.call('HLEN', pd) >= 1024
        or tonumber(redis.call('HGET', pc, scope) or '0') >= 64
        or redis.call('HEXISTS', pd, id) == 1 then return {} end
    redis.call('HSET', pd, id, value)
    redis.call('ZADD', pe, expires, id)
    redis.call('HINCRBY', pc, scope, 1)
    for _, key in ipairs({pd, pe, pc}) do redis.call('PEXPIRE', key, 301000) end
    return {'ok'}
elseif op == 'consume' then
    local record = redis.call('HGET', pd, id)
    if not record then return {} end
    if tonumber(redis.call('ZSCORE', pe, id) or '0') <= now then drop_pending(id); return {} end
    local flow = cjson.decode(record)
    -- Wrong browser or policy must not consume a legitimate pending flow.
    if flow.scope ~= scope or flow.browser_hash ~= value then return {} end
    drop_pending(id)
    return {record}
elseif op == 'create' then
    prune(sd, se, false)
    if tonumber(expires) <= now or redis.call('HLEN', sd) >= 8192
        or redis.call('HEXISTS', sd, id) == 1 then return {} end
    redis.call('HSET', sd, id, scope)
    redis.call('ZADD', se, expires, id)
    redis.call('PEXPIRE', sd, 86401000)
    redis.call('PEXPIRE', se, 86401000)
    return {remaining(id, scope)}
elseif op == 'get' then return {remaining(id, scope)}
elseif op == 'check' then
    local result = {}
    for i = 2, #ARGV, 2 do result[#result + 1] = remaining(ARGV[i], ARGV[i + 1]) end
    return result
elseif op == 'revoke' then
    if redis.call('HGET', sd, id) == scope then
        redis.call('HDEL', sd, id); redis.call('ZREM', se, id)
    end
    return {'ok'}
end
return redis.error_reply('unknown visitor store operation')
