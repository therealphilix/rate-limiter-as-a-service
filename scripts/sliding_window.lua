-- sliding_window.lua
-- Called with: KEYS[1] = redis key, ARGV[1] = now (unix ms), ARGV[2] = window (ms), ARGV[3] = limit
--
-- This entire script runs atomically inside Redis — no other command from any
-- other client can execute between these lines. That's the whole point of Lua
-- in Redis: read-modify-write with no race condition.

local key          = KEYS[1]
local now          = tonumber(ARGV[1])   -- current time in milliseconds
local window_ms    = tonumber(ARGV[2])   -- window size in milliseconds
local limit        = tonumber(ARGV[3])   -- max requests allowed in window

local window_start = now - window_ms

-- 1. Evict all entries older than the window boundary.
--    ZREMRANGEBYSCORE removes members whose score falls in (-inf, window_start].
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- 2. Count how many requests are currently inside the window.
local count = redis.call('ZCARD', key)

if count < limit then
    -- 3a. Under the limit — record this request.
    --     The member value is "timestamp-random" to guarantee uniqueness even
    --     if two requests arrive in the same millisecond. The score IS the
    --     timestamp so we can range-query it later.
    local member = now .. '-' .. math.random(1, 1000000)
    redis.call('ZADD', key, now, member)

    -- Set the key to expire after the window so Redis auto-cleans idle keys.
    -- EXPIRE takes seconds; convert from ms.
    local window_seconds = math.ceil(window_ms / 1000)
    redis.call('EXPIRE', key, window_seconds)

    -- Return: { allowed=1, remaining=N, retry_after=0 }
    return { 1, limit - count - 1, 0 }
else
    -- 3b. Over the limit — find when the oldest entry exits the window.
    --     ZRANGE key 0 0 WITHSCORES returns the member with the lowest score
    --     (i.e. the oldest request). retry_after is how long until that entry
    --     falls outside the window and frees up a slot.
    local oldest      = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local oldest_ts   = tonumber(oldest[2])
    local retry_after = math.ceil((window_ms - (now - oldest_ts)) / 1000)

    -- Return: { allowed=0, remaining=0, retry_after=N_seconds }
    return { 0, 0, retry_after }
end