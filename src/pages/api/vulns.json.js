/**
 * src/pages/api/vulns.json.js
 *
 * this-endpoint > GET /pages/vulns.json
 *
 * merges the  harvest file (vulns.json, written by snyk-harvest.zsh)
 * with a live `npm audit --json` run.  Snyk 'wins' on severity race.
 *
 * NOTE:
 *   1. lib/load-vulns.mjs or tweak pathing below
 *   2. astro.config.mjs must have output: 'server' OR use a hybrid adapter
 *      so this endpoint runs server-side.
 *
 * ENV VARS (same ones snyk-harvest.zsh uses)
 *   SNYK_VULNS_FILE   path to the normalized vulns.json symlink
 *                     default: pages/vulns.json
 *
 * endpoint is intentionally simple — all the merging logic lives in
 * load-vulns.mjs. allows for tests standalone: `node load-vulns.mjs`.
 */

import { loadVulns } from '../../lib/load-vulns.mjs';

// Astro API route — Just the GET baby, just the GET
export const prerender = false;

export async function GET({ request }) {
  try {
    const data = await loadVulns();

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        // Don't cache stale vuln data in the browser.
        'Cache-Control': 'no-store',
        // Basic hardening — why it shouldn't be embedded
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
