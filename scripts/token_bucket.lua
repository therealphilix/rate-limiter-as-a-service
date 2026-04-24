-- token_bucket.lua
-- KEYS[1]  = redis key
-- ARGV[1]  = capacity       (max tokens)
-- ARGV[2]  = refill_rate    (tokens per second, can be fractional e.g. 0.5)
-- ARGV[3]  = now            (unix timestamp in seconds, fractional)
--
-- The bucket state is stored as a Redis hash with two fields:
--   tokens      — current token count (float stored as string)
--   last_refill — timestamp of the last refill (float stored as string)
--
-- Why a hash instead of two separate keys?
--   HMGET and HMSET operate on both fields in one round trip, keeping the
--   read-modify-write truly atomic within this script.
--
-- The key insight — lazy refill:
--   We never run a background job to add tokens. Instead, every time a
--   request arrives we calculate how many tokens have accumulated since the
--   last request and add them now. The bucket is "refilled" on demand.
--   This pattern (lazy evaluation) comes up constantly in distributed systems.

local key         = KEYS[1]
local capacity    = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now         = tonumber(ARGV[3])

-- Read current bucket state (returns {tokens, last_refill} or {false, false})
local bucket      = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens      = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

-- First request ever for this key — bucket starts full
if tokens == nil then
    tokens      = capacity
    last_refill = now
end

-- Lazy refill: calculate tokens accumulated since last request
local elapsed    = now - last_refill
local new_tokens = tokens + (elapsed * refill_rate)

-- Cap at capacity — the bucket can't overflow
if new_tokens > capacity then
    new_tokens = capacity
end

if new_tokens >= 1 then
    -- Consume one token and allow the request
    local after_consume = new_tokens - 1
    redis.call('HMSET', key, 'tokens', after_consume, 'last_refill', now)
    -- Expire after (capacity / refill_rate) * 2 seconds of inactivity
    -- i.e. long enough for a full bucket to be relevant, then clean up
    local ttl = math.ceil((capacity / refill_rate) * 2)
    redis.call('EXPIRE', key, ttl)

    -- Return: { allowed=1, remaining=floor(tokens_left), retry_after=0 }
    return { 1, math.floor(after_consume), 0 }
else
    -- Not enough tokens — calculate wait time
    -- We need (1 - new_tokens) more tokens, arriving at refill_rate per second
    local deficit     = 1 - new_tokens
    local retry_after = math.ceil(deficit / refill_rate)

    -- Still update last_refill and token count so the next request
    -- calculates elapsed time from now, not from the stale last_refill
    redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil((capacity / refill_rate) * 2))

    -- Return: { allowed=0, remaining=0, retry_after=N }
    return { 0, 0, retry_after }
end