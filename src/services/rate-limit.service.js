/**
 * Rate limiting / brute-force protection.
 *
 * Two cooperating layers:
 *  1. an in-process fixed-window counter (cheap, per-IP generic endpoints);
 *  2. a persistent bucket in `login_attempts` (survives restarts, so an
 *     attacker cannot reset the counter by forcing a container restart).
 *
 * A back-off is applied per bucket key, e.g. `login:ip:<hash>|email:x@y.z`.
 */
import { logger } from '../utils/logger.js';

export function createRateLimitService(db, { max, windowMs }) {
  const buckets = new Map();
  let lastSweep = Date.now();

  function sweep(now = Date.now()) {
    if (now - lastSweep < windowMs) return;
    lastSweep = now;
    for (const [key, b] of buckets) {
      if (now - b.first >= windowMs && !(b.lockedUntil && b.lockedUntil > now)) buckets.delete(key);
    }
  }

  /**
   * @returns {{allowed:boolean, remaining:number, retryAfterMs:number, count:number, lockedUntil:string|null}}
   */
  function consume(key, cost = 1, over = {}) {
    const now = Date.now();
    sweep(now);
    const limit = over.max ?? max;
    const win = over.windowMs ?? windowMs;
    const bucket = buckets.get(key) ?? { count: 0, first: now, lockedUntil: 0 };
    if (now - bucket.first >= win) {
      bucket.count = 0;
      bucket.first = now;
      bucket.lockedUntil = 0;
    }
    if (bucket.lockedUntil && bucket.lockedUntil > now) {
      buckets.set(key, bucket);
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: bucket.lockedUntil - now,
        count: bucket.count,
        lockedUntil: new Date(bucket.lockedUntil).toISOString(),
      };
    }
    bucket.count += cost;
    const allowed = bucket.count <= limit;
    if (!allowed) {
      bucket.lockedUntil = now + (over.blockMs ?? win);
      logger.warn('rate limit atteint', { key: key.slice(0, 48), count: bucket.count, limit });
    }
    buckets.set(key, bucket);
    return {
      allowed,
      remaining: Math.max(0, limit - bucket.count),
      retryAfterMs: allowed ? 0 : bucket.lockedUntil - now,
      count: bucket.count,
      lockedUntil: bucket.lockedUntil > now ? new Date(bucket.lockedUntil).toISOString() : null,
    };
  }

  function reset(key) {
    buckets.delete(key);
  }

  function peek(key) {
    const b = buckets.get(key);
    if (!b) return { count: 0, lockedUntil: null };
    return { count: b.count, lockedUntil: b.lockedUntil > Date.now() ? new Date(b.lockedUntil).toISOString() : null };
  }

  /* ---------- persistent login buckets (shared with the account lockout) --- */

  function loginBucketConsume(key, { limit, windowMs: w, lockMs }) {
    const now = new Date();
    const row = db.get(`SELECT count, first_at, locked_until FROM login_attempts WHERE bucket_key = ?`, [key]);
    const firstAt = row?.first_at ? new Date(row.first_at) : now;
    const withinWindow = row && now - firstAt <= w;
    const count = withinWindow ? (row.count ?? 0) + 1 : 1;
    const shouldLock = count >= limit;
    const lockedUntil = shouldLock ? new Date(Date.now() + lockMs).toISOString() : withinWindow ? row.locked_until ?? null : null;
    if (row) {
      db.run(
        `UPDATE login_attempts SET count = ?, first_at = ?, last_at = ?, locked_until = ?, revised_at = ? WHERE bucket_key = ?`,
        [count, withinWindow ? firstAt.toISOString() : now.toISOString(), now.toISOString(), lockedUntil, now.toISOString(), key],
      );
    } else {
      db.run(
        `INSERT INTO login_attempts (bucket_key, count, first_at, last_at, locked_until, revised_at) VALUES (?,?,?,?,?,?)`,
        [key, count, now.toISOString(), now.toISOString(), lockedUntil, now.toISOString()],
      );
    }
    return { count, lockedUntil, remaining: Math.max(0, limit - count) };
  }

  function loginBucketReset(key) {
    db.run(`DELETE FROM login_attempts WHERE bucket_key = ?`, [key]);
  }

  function loginBucketPeek(key) {
    const row = db.get(`SELECT count, first_at, locked_until FROM login_attempts WHERE bucket_key = ?`, [key]);
    if (!row) return { count: 0, lockedUntil: null };
    return { count: row.count, lockedUntil: row.locked_until };
  }

  function blockedBuckets(limit = 25) {
    return db.all(
      `SELECT bucket_key, count, last_at, locked_until FROM login_attempts
        WHERE locked_until IS NOT NULL ORDER BY last_at DESC LIMIT ?`,
      [limit],
    );
  }

  return { consume, reset, peek, loginBucketConsume, loginBucketReset, loginBucketPeek, blockedBuckets, sweep };
}

export default createRateLimitService;
