const LEAD_RETENTION_SECONDS = 365 * 24 * 60 * 60;
const LEGACY_LEAD_LIST = 'zapqueme:leads';

// Remove the old fallback format, which stored full lead JSON in a Redis list.
// New entries contain only random IDs in that list; the lead hash has its own TTL.
export async function pruneRedisLeadFallback() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return { checked: 0, removed: 0 };

  try {
    let checked = 0;
    let removed = 0;
    let offset = 0;
    const pageSize = 200;

    while (true) {
      const response = await fetch(`${url}/lrange/${LEGACY_LEAD_LIST}/${offset}/${offset + pageSize - 1}`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(5000)
      });
      if (!response.ok) throw new Error(`Redis HTTP ${response.status}`);

      const data = await response.json();
      const values = Array.isArray(data.result) ? data.result : [];
      if (!values.length) break;
      checked += values.length;

      const now = Date.now();
      const expiredValues = values.filter(value => {
        const raw = String(value ?? '');
        if (!raw.startsWith('{')) return false; // ID-only entry; its value key has a TTL.
        try {
          const lead = JSON.parse(raw);
          const createdAt = Date.parse(lead?.criado_em);
          return !Number.isFinite(createdAt) || now - createdAt >= LEAD_RETENTION_SECONDS * 1000;
        } catch {
          return true;
        }
      });

      if (expiredValues.length) {
        const pipeline = expiredValues.map(value => ['LREM', LEGACY_LEAD_LIST, 1, value]);
        const removeResponse = await fetch(`${url}/pipeline`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(pipeline),
          signal: AbortSignal.timeout(10000)
        });
        if (!removeResponse.ok) throw new Error(`Redis cleanup HTTP ${removeResponse.status}`);
        const results = await removeResponse.json();
        if (results.some(item => item?.error)) throw new Error('Redis cleanup command failed');
        removed += expiredValues.length;
      }

      const keptInPage = values.length - expiredValues.length;
      if (values.length < pageSize) break;
      offset += keptInPage;
    }

    const expireResponse = await fetch(`${url}/expire/${LEGACY_LEAD_LIST}/${LEAD_RETENTION_SECONDS}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(5000)
    });
    if (!expireResponse.ok) throw new Error(`Redis index expiry HTTP ${expireResponse.status}`);

    return { checked, removed };
  } catch (error) {
    console.warn(`[Retention] Redis lead cleanup unavailable: ${error.message}`);
    return { checked: 0, removed: 0, unavailable: true };
  }
}

export { LEAD_RETENTION_SECONDS };
