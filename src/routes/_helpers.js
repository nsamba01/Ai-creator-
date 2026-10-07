/** Shared route helpers. */

/** Wraps an async handler so rejections always reach the error middleware. */
export const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

export const noStore = (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  next();
};

/**
 * CSV serialisation with formula-injection protection: a cell starting with
 * = + - @ or a tab/CR is prefixed with an apostrophe so Excel/Sheets never
 * evaluate it as a formula.
 */
export function csvCell(value) {
  let s = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  if (/[";\n\r,]/.test(s)) s = `"${s.replace(/"/g, '""')}"`;
  return s;
}

export function toCsv(rows, columns) {
  const head = columns.map((c) => csvCell(c.label ?? c.key)).join(',');
  const body = rows.map((r) => columns.map((c) => csvCell(typeof c.value === 'function' ? c.value(r) : r[c.key])).join(','));
  return [head, ...body].join('\r\n') + '\r\n';
}

/** Basic pagination parsing (never trusts client-supplied offsets). */
export function pagination(query, { limit = 50, max = 200 } = {}) {
  const rawLimit = Number.parseInt(String(query.limit ?? ''), 10);
  const rawOffset = Number.parseInt(String(query.offset ?? ''), 10);
  return {
    limit: Number.isFinite(rawLimit) ? Math.min(max, Math.max(1, rawLimit)) : limit,
    offset: Number.isFinite(rawOffset) ? Math.max(0, rawOffset) : 0,
  };
}
