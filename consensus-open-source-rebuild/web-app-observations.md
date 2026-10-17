# consensus.app web client: public-surface observations

**Observed:** 2026-10-17, Next.js build `veQhXo0FXl0OhxebvT5WO`.
**Method:** REA+ (`capture-browser-scenario`, `analyze-web-bundle`,
`analyze-javascript-application`), plus string searches over the same
publicly served JavaScript.

These are clean-room notes: what an anonymous visitor's browser receives
and does. No Consensus code, assets or private data are copied here, and
public client keys (Clerk publishable key, Statsig client key) are left out
on purpose. Each item says whether it was **observed** live, **found** in
the shipped JavaScript, or **inferred**.

## Boundaries of this pass

- One anonymous page load of `/`, then one of `/search/`, in headless
  Chromium. No login, no form submission, no search query.
- On the first load, the page rendered, but every first-party `/api/...`
  call returned **403**. A Cloudflare bot-management script
  (`cdn-cgi/challenge-platform/.../jsd`) was running.
- The second load (`/search/`) got a Cloudflare **challenge page** instead
  of the app. Live observation stopped there. The challenge was not solved,
  spoofed or bypassed.
- The 12 Next.js chunks the homepage loaded were then fetched once each
  (1 s apart, per robots.txt `Crawl-delay: 1`), with byte sizes identical
  to what the browser received.
- Server-side code, request/response schemas and model configuration are
  not visible from the client. Paths below say where requests go, not what
  they carry.

## Stack

| Layer | What | How known |
| --- | --- | --- |
| Web framework | Next.js, pages router (`_next/data/<build>/*.json`, `_buildManifest.js`); React | observed, found |
| HTTP client | Axios instance with `baseURL: "/api"` in the browser and a server `HOST` during SSR; 300 s timeout | found |
| State and rendering | Redux; `marked` for Markdown | found (doc links in bundle) |
| Auth | Clerk, Frontend API on `clerk.consensus.app`; enterprise SSO discovery; OAuth consent page | observed, found |
| Feature flags | Statsig, through the proxy domains `featureassets.org` and `prodregistryv2.org` | observed |
| Product analytics | Mixpanel through `track.consensus.app`, plus a first-party `/api/track_event/` | observed |
| Monitoring | Datadog RUM (US3 site); Cloudflare Web Analytics | observed |
| Edge | Cloudflare, with bot management and challenges | observed |
| Device fingerprinting | FingerprintJS (`fpjs.dev`, `openfpcdn.io`) | found |
| Billing | Stripe subscriptions (`api_stripe_subscription/...`); Churnkey for cancel and pause flows | found |
| Marketing | Google Tag Manager / GA4, DoubleClick, Meta Pixel, LinkedIn Insight, HubSpot (forms, CTAs, cookie banner), Intercom (help center at `help.consensus.app`) | observed |
| Marketing site | WordPress under `/home/` (robots.txt rules for `wp-content`, `wp-admin`) | inferred |
| PWA | Web manifest; a service worker the capture blocked | observed |

Other hosts referenced in the bundle:

- Semantic Scholar and doi.org, used in paper links.
- SCImago journal rankings.
- claude.ai, chatgpt.com and the Microsoft marketplace, likely integration
  pages.
- `status.openai.com`. This suggests OpenAI is at least one model vendor;
  it is an inference.

## Product surface (homepage, anonymous)

The rendered page (accessibility tree) is a chat-style research assistant:

- **Thread controls:** a "New Thread" sidebar button, an "Ask the research…"
  input, and a **Sources** button.
- **Disabled until sign-in:** **Skills**, the **Deep** switch and the submit
  button.
- **Other controls:** a **Filter** button.
- **Quick actions:** "Find promising research questions", "Quick TL;DR",
  "Build a comparison table".
- **Claims:** "400M+ peer reviewed research papers" (sidebar) and "250M+
  research papers, including licensed full text" (body). Publisher logos
  include Wiley, Taylor & Francis, Sage, APA and AAAS.

Feature gates evaluated for an anonymous visitor (Statsig warnings):

- `mobile_linkout_cta_enabled`
- `freemium_vs_trial_enabled`
- `home_page_announcement_banner`, with config `home_page_banner_content`
- `deep_mode_attachments_enabled`
- `skills_user_invocation_enabled`
- `annual_only_academic_discount_enabled`
- `expiring_university_trial_notice_enabled` and
  `expired_university_trial_notice_enabled`, with configs
  `expiring_university_trial_allowlist` and
  `expired_university_trial_notice_audience`

## Page routes (from `_buildManifest.js`)

46 routes, including:

| Area | Routes |
| --- | --- |
| Search and threads | `/search`, `/search/new`, `/search/[title]/[id]`, `/search/[title]/new`, `/results`, `/quick`, `/threads/[threadId]/interactions/[interactionId]/export` |
| Papers | `/papers/[title]/[id]`, `/papers/uploaded/[id]`, `/questions/[slug]` (SEO question pages) |
| Analysis tools | `/extract`, `/extract/[id]` (comparison tables), `/graph` (citation graph) |
| Library | `/library/[[...index]]`, `/lists/[id]`, `/hub`, `/hub/[tab]`, `/history` |
| Sharing and teams | `/shared/[[...index]]`, `/shared/invite/[token]`, `/organization/[[...index]]` |
| Account and auth | `/sign-in/...` (including SSO callbacks), `/sign-up`, `/sign-up/onboarding`, `/sso`, `/oauth/consent`, `/password-reset`, `/settings/[[...index]]`, `/account` |
| Billing | `/pricing/[[...slug]]`, `/subscription`, `/subscription/api`, `/claim_coupon` |
| Developer | `/api-mcp` |
| Machine-readable | `/llms-full.txt`, `/sitemap.xml`, `/robots.txt`, `/status` |

## API surface (paths under `https://consensus.app/api/`)

These were found as literal or template strings passed to the Axios client.
`{id}` marks a runtime value.

**Threads and answers.** A thread is a sequence of *interactions*, each an
agent run over a search:

- `threads/`, `threads/{id}/`, `threads/{id}/fork/`,
  `threads/{id}/generate-title/`
- `threads/{id}/interactions/{id}/`, and under it:
  - `agent/answer/` and `agent/retry/{n}`;
  - `cited_content/`, the passages the answer cites;
  - `papers/`;
  - `review/`;
  - `yes_no/` and `yes_no/analysis/`, likely the Consensus Meter;
  - `legacy_search_strategy_stats/`.
- `/api/threads/{id}/interactions/{id}/agent/stream/` streams the answer.
  The client reads it through `fetch` stream readers, not WebSockets.
- `/api/threads/{id}/interactions/{id}/export/`
- `feedback/thread`

**Search and papers:**

- `paper_search/`, `paper_search/{id}/takeaway_translations/`,
  `paper_search/{id}/yes_no/` and `/yes_no/analysis/`
- `pro_agent/group-results/{id}` (Pro mode result grouping)
- `papers/details/`, `papers/details/{id}/`, `papers/related/{id}/`,
  `papers/pdf/{id}`
- `study_details/{id}`, likely Study Snapshot
- `publishers/filter_options/`, `search_feed/queries`, `example_queries`
- `citation_graph/`, `citation_graph/generate-title/`
- `research_gap_matrix/`

**Comparison tables (`extraction_tables`).** These are per-column
extraction runs over a set of papers:

- `extraction_tables/`, `extraction_tables/presets/`,
  `extraction_tables/{id}/`
- under `extraction_tables/{id}/`: `papers/`, `runs/`, `fork/`,
  `generate-title/`
- per column: `columns/{id}/`, plus `columns/{id}/order/`,
  `columns/{id}/visibility/`, `columns/{id}/runs/` and
  `columns/{id}/papers/{id}/runs/`

**Library and uploads:**

- `collections/` and per-collection `papers/`, `threads/`,
  `extraction_tables/`, `organization-memberships/`
- `collections/{id}/papers/import-by-doi/` and `import-by-file/`
- reverse lookups `collections/by-paper/` and `by-thread/`
- `papers/uploaded/`, `papers/uploaded/{id}/download`,
  `papers/uploaded/matched-mappings/`
- Zotero: `zotero/oauth/start/`, `zotero/oauth/claim/`, `zotero/connect/`,
  `zotero/disconnect/`, `zotero/import/`, `zotero/import/{id}/status/`,
  `zotero/info/`, `zotero/info/collection_counts/`, `zotero/status/`,
  `zotero/onboarding-queries/`

**Developer product.** API keys and MCP access are billed in credits:

- `api_keys/user`, `api_keys/dashboard_scope`
- `mcp_clients/`
- `mcp_credits/`, `mcp_credits/activity`, `mcp_credits/billing`,
  `mcp_credits/held/`, `mcp_credits/paid_invoices`,
  `mcp_credits/organization/{id}` (and `/activity`)

**Account, billing and other:**

- `user/usage`, `user/allowance`, `subscription_products/`,
  `pricing/plans/`, `pricing/team`
- `api_stripe_subscription/team/{id}` (and invoices),
  `get_stripe_subscription/team/{id}`
- `/api/subscription?action=unpauseSubscription`, `/api/churnkey`
- `verified_student_email/`, `/api/validate_student_email/`
- `auth/enterprise-sso-discovery`
- `voice_transcription/` (dictation), `status/`, `waitlist`,
  `update_mixpanel_user_profile/`, `track_event/`
- Open Graph images: `/api/og/papers`, `/api/og/questions`,
  `/api/og/threads`, `/api/og/extract`

## What this suggests for the rebuild

These are design inputs, not claims about Consensus's internals:

- **Threads of interactions.** Each follow-up question is an interaction
  with its own search, papers, cited passages and optional yes/no analysis.
  Threads can be forked, titled, shared and exported.
- **A streamed agent answer.** The answer is a long-running agent run
  streamed to the client, with retry by attempt number. Citations are a
  separate resource (`cited_content`) rather than inline-only.
- **Separate meter endpoints.** The yes/no "meter" is its own endpoint
  pair (a classification, then an analysis). Translations of per-paper
  takeaways are separate too.
- **Comparison tables.** A table is a grid of papers × columns, with an
  extraction "run" per column and per cell. Presets, ordering, visibility
  and forking make it reusable.
- **Library.** The library is collections holding papers, threads and
  tables. Imports come by DOI, file or Zotero OAuth.
- **Developer access.** The same capabilities are sold to agents through
  MCP with credit accounting, OAuth consent and API keys.

## Not answered by this pass

- Request and response schemas, ranking, corpus sources and model choice.
  These are server-side, and live API calls were refused (403 / Cloudflare
  challenge).
- The contents of chunks that load only on other pages (search results,
  paper pages, extraction tables). They would show the UI shapes behind
  the endpoints above.
- The Android app (`app.consensus.android`), which has not been analyzed;
  see the README's next milestone.

## REA+ gaps found while doing this

- `capture-browser-scenario` launch mode does not pass `HTTPS_PROXY` (or
  `HTTP_PROXY`/`NO_PROXY`) to the browser it starts. Behind this
  environment's TLS-inspecting proxy the load failed with
  `ERR_CERT_AUTHORITY_INVALID`. Connect mode, with a self-started
  Chromium, worked.
- `list-browser-targets` lists only HTTP(S) pages, so a fresh browser on
  `about:blank` needs a page opened first.
- `analyze-web-bundle` reports endpoints passed as literal strings (about
  30 here) but not template-literal paths (about 130 more in the same
  chunk).
- `analyze-javascript-application` skipped semantic analysis of the 4.5 MB
  `_app` chunk because it exceeded the result budget.
