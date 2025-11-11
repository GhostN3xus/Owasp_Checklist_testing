interface RateLimitStore {
  [key: string]: { count: number; resetTime: number };
}

const store: RateLimitStore = {};

export function rateLimit(
  identifier: string,
  limit: number = 100,
  window: number = 60000
): boolean {
  const now = Date.now();
  const key = identifier;

  if (!store[key]) {
    store[key] = { count: 1, resetTime: now + window };
    return true;
  }

  if (now > store[key].resetTime) {
    store[key] = { count: 1, resetTime: now + window };
    return true;
  }

  store[key].count++;

  if (store[key].count > limit) {
    return false;
  }

  return true;
}

export function isRateLimited(identifier: string): boolean {
  return !rateLimit(identifier);
}
