/**
 * Zero Project — read-only API Worker over the D1 database.
 *
 * Endpoints:
 *   GET /api/weeks?from=&to=            kev_weekly rows in [from,to] (ISO Monday dates)
 *   GET /api/week/{YYYY-MM-DD}          KEV entries added that ISO week, joined with epss/exploit/ssvc
 *   GET /api/cve/{id}                   one CVE: kev entry (if any) + epss + exploit signals + ssvc
 *   GET /api/vendors?week=              vendor_weekly rows for a given week
 *   GET /api/products/{id}              watchlist_monthly rows for a product id
 *   GET /api/search?q=                  LIKE search over cve/vendor/product/name, limit 50
 *   GET /api/stats                      row-count totals + last refresh timestamp
 *
 * All responses are JSON with CORS "*" and Cache-Control: public, max-age=3600.
 * Rate limiting relies on Cloudflare Workers free-tier defaults (no custom limiter).
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
      ...CORS,
    },
  });
}

function isValidDate(s) {
  return /^\d{4}-\d{2}-\d{2}$/.test(s);
}

function addDays(dateStr, n) {
  const d = new Date(dateStr + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const db = env.DB;

    try {
      // GET /api/weeks?from=&to=
      if (path === "/api/weeks") {
        const from = url.searchParams.get("from");
        const to = url.searchParams.get("to");
        let sql = "SELECT week, total, fresh, older, ransom, median_tte, edge FROM kev_weekly";
        const params = [];
        const clauses = [];
        if (from && isValidDate(from)) {
          clauses.push("week >= ?");
          params.push(from);
        }
        if (to && isValidDate(to)) {
          clauses.push("week <= ?");
          params.push(to);
        }
        if (clauses.length) sql += " WHERE " + clauses.join(" AND ");
        sql += " ORDER BY week ASC";
        const { results } = await db.prepare(sql).bind(...params).all();
        return json({ weeks: results });
      }

      // GET /api/week/{YYYY-MM-DD}
      let m = path.match(/^\/api\/week\/([0-9-]+)$/);
      if (m) {
        const week = m[1];
        if (!isValidDate(week)) return json({ error: "invalid week, expected YYYY-MM-DD" }, 400);
        const weekEnd = addDays(week, 6);
        const { results: entries } = await db
          .prepare(
            `SELECT e.*, ep.score AS epss_score, ep.percentile AS epss_percentile,
                    x.msf, x.edb, x.poc,
                    s.exploitation, s.automatable, s.impact
             FROM kev_entries e
             LEFT JOIN epss ep ON ep.cve = e.cve
             LEFT JOIN exploit_signals x ON x.cve = e.cve
             LEFT JOIN ssvc s ON s.cve = e.cve
             WHERE e.date_added BETWEEN ? AND ?
             ORDER BY e.date_added ASC`
          )
          .bind(week, weekEnd)
          .all();
        const weekly = await db
          .prepare("SELECT week, total, fresh, older, ransom, median_tte, edge FROM kev_weekly WHERE week = ?")
          .bind(week)
          .first();
        return json({ week, summary: weekly || null, entries });
      }

      // GET /api/cve/{id}
      m = path.match(/^\/api\/cve\/(CVE-[0-9-]+)$/i);
      if (m) {
        const cve = m[1].toUpperCase();
        const [entry, epss, exploit, ssvc] = await Promise.all([
          db.prepare("SELECT * FROM kev_entries WHERE cve = ?").bind(cve).first(),
          db.prepare("SELECT * FROM epss WHERE cve = ?").bind(cve).first(),
          db.prepare("SELECT * FROM exploit_signals WHERE cve = ?").bind(cve).first(),
          db.prepare("SELECT * FROM ssvc WHERE cve = ?").bind(cve).first(),
        ]);
        if (!entry && !epss && !exploit && !ssvc) return json({ error: "not found" }, 404);
        return json({ cve, kev: entry || null, epss: epss || null, exploit: exploit || null, ssvc: ssvc || null });
      }

      // GET /api/vendors?week=
      if (path === "/api/vendors") {
        const week = url.searchParams.get("week");
        let sql = "SELECT week, cna, high_critical FROM vendor_weekly";
        const params = [];
        if (week) {
          if (!isValidDate(week)) return json({ error: "invalid week, expected YYYY-MM-DD" }, 400);
          sql += " WHERE week = ?";
          params.push(week);
        }
        sql += " ORDER BY high_critical DESC LIMIT 500";
        const { results } = await db.prepare(sql).bind(...params).all();
        return json({ week: week || null, vendors: results });
      }

      // GET /api/products/{id}
      m = path.match(/^\/api\/products\/([a-z0-9._-]+)$/i);
      if (m) {
        const productId = m[1];
        const { results } = await db
          .prepare(
            "SELECT product_id, month, total, critical, high, medium, low FROM watchlist_monthly WHERE product_id = ? ORDER BY month ASC"
          )
          .bind(productId)
          .all();
        if (!results.length) return json({ error: "not found" }, 404);
        return json({ product_id: productId, monthly: results });
      }

      // GET /api/search?q=
      if (path === "/api/search") {
        const q = (url.searchParams.get("q") || "").trim();
        if (!q) return json({ error: "missing q" }, 400);
        const like = `%${q}%`;
        const { results } = await db
          .prepare(
            `SELECT date_added, cve, vendor, product, name, severity
             FROM kev_entries
             WHERE cve LIKE ? OR vendor LIKE ? OR product LIKE ? OR name LIKE ?
             ORDER BY date_added DESC
             LIMIT 50`
          )
          .bind(like, like, like, like)
          .all();
        return json({ q, results });
      }

      // GET /api/stats
      if (path === "/api/stats") {
        const [kevCount, ledgerWeeks, vendorRows, watchlistRows, epssRows, exploitRows, ssvcRows, advisoryRows, lastRefresh] =
          await Promise.all([
            db.prepare("SELECT count(*) n FROM kev_entries").first("n"),
            db.prepare("SELECT count(*) n FROM ledger_weekly").first("n"),
            db.prepare("SELECT count(*) n FROM vendor_weekly").first("n"),
            db.prepare("SELECT count(*) n FROM watchlist_monthly").first("n"),
            db.prepare("SELECT count(*) n FROM epss").first("n"),
            db.prepare("SELECT count(*) n FROM exploit_signals").first("n"),
            db.prepare("SELECT count(*) n FROM ssvc").first("n"),
            db.prepare("SELECT count(*) n FROM advisories").first("n"),
            db.prepare("SELECT value FROM meta WHERE key = 'last_refresh'").first("value"),
          ]);
        return json({
          totals: {
            kev_entries: kevCount,
            ledger_weeks: ledgerWeeks,
            vendor_weekly_rows: vendorRows,
            watchlist_monthly_rows: watchlistRows,
            epss_rows: epssRows,
            exploit_signal_rows: exploitRows,
            ssvc_rows: ssvcRows,
            advisory_rows: advisoryRows,
          },
          last_refresh: lastRefresh || null,
        });
      }

      return json({ error: "not found", routes: [
        "/api/weeks?from=&to=",
        "/api/week/{YYYY-MM-DD}",
        "/api/cve/{id}",
        "/api/vendors?week=",
        "/api/products/{id}",
        "/api/search?q=",
        "/api/stats",
      ] }, 404);
    } catch (err) {
      return json({ error: "internal error", message: String(err && err.message || err) }, 500);
    }
  },
};
