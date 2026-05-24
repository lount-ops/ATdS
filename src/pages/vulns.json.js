/**
 * src/pages/api/vulns.json.js
 *
 * Astro API endpoint → GET /api/vulns.json
 *
 * Merges the Snyk harvest file (vulns.json, written by snyk-harvest.zsh)
 * with a live `npm audit --json` run.  Snyk wins on severity ties.
 *
 * SETUP
 *   1. Copy load-vulns.mjs to src/lib/load-vulns.mjs (or keep at project root
 *      and adjust the import path below).
 *   2. Your astro.config.mjs must have output: 'server' OR use a hybrid adapter
 *      so this endpoint runs server-side.  Static output won't work here.
 *
 * ENV VARS (same ones snyk-harvest.zsh uses)
 *   SNYK_VULNS_FILE   path to the normalized vulns.json symlink
 *                     default: <project-root>/vulns.json
 *
 * The endpoint is intentionally simple — all the merge logic lives in
 * load-vulns.mjs so it can be tested standalone with `node load-vulns.mjs`.
 */

import { loadVulns } from '../../lib/load-vulns.mjs';

// Astro API route — only GET makes sense here
export const prerender = false;

export async function GET({ request }) {
  try {
    const data = await loadVulns();

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        // Don't cache stale vuln data in the browser.
        // CDN/proxy: feel free to bump s-maxage if you're behind Cloudflare.
        'Cache-Control': 'no-store',
        // Basic hardening — this endpoint has no business being embedded
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
      },
    });

  } catch (err) {
    console.error('[/api/vulns.json] loadVulns failed:', err);

    return new Response(
      JSON.stringify({ error: 'Failed to load vulnerability data', detail: err.message }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }
}
