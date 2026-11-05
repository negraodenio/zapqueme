import crypto from 'node:crypto';

export function secureEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || !left || !right) return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function getClientIp(req) {
  const forwarded = req.headers?.['x-forwarded-for'];
  const candidate = (Array.isArray(forwarded) ? forwarded[0] : forwarded)?.split(',')[0]?.trim();
  return candidate || req.headers?.['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}

export async function checkRateLimit(req, namespace, limit, windowSeconds) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  const failClosed = process.env.NODE_ENV === 'production';

  if (!url || !token) {
    return failClosed
      ? { allowed: false, unavailable: true }
      : { allowed: true, unavailable: false };
  }

  const window = Math.floor(Date.now() / (windowSeconds * 1000));
  const ipHash = crypto.createHash('sha256').update(getClientIp(req)).digest('hex').slice(0, 32);
  const key = `ratelimit:${namespace}:${ipHash}:${window}`;

  try {
    const response = await fetch(`${url}/pipeline`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify([
        ['INCR', key],
        ['EXPIRE', key, windowSeconds * 2]
      ]),
      signal: AbortSignal.timeout(2500)
    });
    if (!response.ok) throw new Error(`Redis HTTP ${response.status}`);

    const results = await response.json();
    if (results.some(item => item?.error)) throw new Error('Redis rate-limit command failed');
    const count = Number(results[0]?.result);
    if (!Number.isFinite(count)) throw new Error('Redis rate-limit returned an invalid count');
    return { allowed: count <= limit, count, unavailable: false };
  } catch (error) {
    console.warn(`[RateLimit] ${namespace} unavailable: ${error.message}`);
    return failClosed
      ? { allowed: false, unavailable: true }
      : { allowed: true, unavailable: true };
  }
}

export function validateTwilioSignature(req, params) {
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const webhookUrl = process.env.TWILIO_WEBHOOK_URL;
  const signatureHeader = req.headers?.['x-twilio-signature'];
  const signature = Array.isArray(signatureHeader) ? signatureHeader[0] : signatureHeader;
  if (!authToken || !webhookUrl || !signature || !params || typeof params !== 'object') return false;

  let signedData = webhookUrl;
  for (const name of Object.keys(params).sort()) {
    const value = params[name];
    if (Array.isArray(value)) {
      for (const item of value) signedData += name + String(item ?? '');
    } else if (value !== undefined && value !== null) {
      signedData += name + String(value);
    }
  }

  const expected = crypto.createHmac('sha1', authToken).update(signedData, 'utf8').digest('base64');
  return secureEqual(expected, String(signature));
}

export function isConfiguredSmsWebhook() {
  return Boolean(process.env.SMS_WEBHOOK_SECRET || (process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_WEBHOOK_URL));
}

export function isAuthorizedSmsWebhook(req, params) {
  const suppliedHeader = req.headers?.['x-sms-webhook-secret'];
  const suppliedSecret = Array.isArray(suppliedHeader) ? suppliedHeader[0] : suppliedHeader;
  if (process.env.SMS_WEBHOOK_SECRET && secureEqual(String(suppliedSecret || ''), process.env.SMS_WEBHOOK_SECRET)) {
    return true;
  }
  return validateTwilioSignature(req, params);
}
