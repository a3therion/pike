-- One namespace/CA directory, with owner-bound per-host leases and fenced writes.
local account, index, state, lease, challenge = unpack(KEYS)
local op, owner, fence = unpack(ARGV)
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
local function owns()
    return redis.call('GET', lease) == fence and redis.call('HGET', state, 'owner') == owner
end
local function retain(ttl)
    ttl = math.max(ttl, redis.call('PTTL', state))
    redis.call('PEXPIRE', state, ttl)
    redis.call('ZADD', index, now + ttl, state)
end
if op == 'account_get' then
    local value = redis.call('GET', account)
    return value and {value} or {}
elseif op == 'account_init' then
    redis.call('SET', account, ARGV[4], 'NX')
    return {redis.call('GET', account)}
elseif op == 'account_finish' then
    local current = redis.call('GET', account)
    if current == ARGV[5] then return {'ok'} end
    if current ~= ARGV[4] then return {} end
    redis.call('SET', account, ARGV[5]); return {'ok'}
elseif op == 'read' then
    local saved_owner = redis.call('HGET', state, 'owner')
    if not saved_owner then return {} end
    return {saved_owner, redis.call('HGET', state, 'version') or '',
        redis.call('HGET', state, 'certificate') or '', redis.call('HGET', state, 'retry_at') or '0'}
elseif op == 'claim' then
    if redis.call('EXISTS', lease) == 1 then return {} end
    if (redis.call('HGET', state, 'version') or '') ~= ARGV[4] then return {} end
    local same_owner = redis.call('HGET', state, 'owner') == owner
    if same_owner and tonumber(redis.call('HGET', state, 'retry_at') or '0') > now then return {} end
    redis.call('ZREMRANGEBYSCORE', index, '-inf', now)
    if not redis.call('ZSCORE', index, state) and redis.call('ZCARD', index) >= 16384 then return {'full'} end
    if not same_owner then redis.call('DEL', state) end
    redis.call('HSET', state, 'owner', owner, 'version', fence)
    retain(86400000)
    redis.call('DEL', challenge)
    redis.call('SET', lease, fence, 'PX', 15000)
    return {'ok'}
elseif op == 'renew' then
    if not owns() then return {} end
    redis.call('PEXPIRE', lease, 15000)
    if redis.call('HGET', challenge, 'lease') == fence then redis.call('PEXPIRE', challenge, 15000) end
    return {'ok'}
elseif op == 'publish' then
    if not owns() or redis.call('EXISTS', challenge) == 1 then return {} end
    redis.call('HSET', challenge, 'owner', owner, 'lease', fence, 'token', ARGV[4], 'value', ARGV[5])
    redis.call('PEXPIRE', challenge, 15000)
    return {'ok'}
elseif op == 'proof' then
    local active = redis.call('GET', lease)
    if not active or redis.call('HGET', state, 'owner') ~= owner
        or redis.call('HGET', challenge, 'owner') ~= owner
        or redis.call('HGET', challenge, 'lease') ~= active
        or redis.call('HGET', challenge, 'token') ~= fence then return {} end
    return {redis.call('HGET', challenge, 'value')}
elseif op == 'commit' then
    if not owns() then return {} end
    redis.call('HSET', state, 'certificate', ARGV[4], 'version', fence, 'failures', 0, 'retry_at', 0)
    retain(math.max(86400000, math.min(400 * 86400000, tonumber(ARGV[5]) * 1000 - now + 86400000)))
    return {'ok'}
elseif op == 'failure' then
    if not owns() then return {} end
    local failures = redis.call('HINCRBY', state, 'failures', 1)
    local retry_at = now + math.min(3600, tonumber(ARGV[4]) * 2 ^ math.min(failures, 6)) * 1000
    redis.call('HSET', state, 'retry_at', retry_at, 'version', fence)
    retain(86400000)
    return {tostring(retry_at)}
elseif op == 'release' then
    if redis.call('GET', lease) == fence then
        redis.call('DEL', lease)
        if redis.call('HGET', challenge, 'lease') == fence then redis.call('DEL', challenge) end
    end
    return {'ok'}
end
return redis.error_reply('unknown ACME coordination operation')
