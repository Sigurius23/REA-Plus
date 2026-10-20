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
  The client opens it with `EventSource`, so it is server-sent events, not
  a WebSocket.
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

**HTTP methods.** A later REA+ pass that follows template and variable-held
URLs (see the gaps section) recovered the method for 145 distinct paths in
the `_app` chunk: 80 GET, 53 POST, 18 DELETE, 9 PATCH and 4 PUT. The ones
that shape the design:

| Path | Methods | Reading |
| --- | --- | --- |
| `paper_search/` | POST | a search is created, then read by id |
| `papers/details/` | POST | batch paper details by id list |
| `threads/` | POST, DELETE | create; bulk delete |
| `threads/{id}/` | GET, POST, PUT, DELETE | read, follow-up, rename/share, delete |
| `threads/{id}/interactions/{id}/agent/answer/` | POST | answer a question the agent asked mid-run |
| `threads/{id}/interactions/{id}/agent/retry/{n}` | POST | rerun an answer |
| `extraction_tables/{id}/runs/`, `columns/{id}/runs/`, `columns/{id}/papers/{id}/runs/` | POST | table-, column- and cell-level extraction runs |
| `collections/{id}/papers/` | POST, DELETE | add/remove papers |
| `collections/{id}/recommendations/` | GET, PATCH | paper recommendations per collection, with `refresh/`, `start-over/`, `{id}/save/` (POST) and `{id}/dismissal/` (PUT, DELETE) |
| `collections/{id}/invite-link/`, `memberships/invitations/`, `organization-memberships/` | GET, POST, PATCH | sharing with people and organizations |
| `citation_graph/`, `research_gap_matrix/` | POST | generated analyses |
| `voice_transcription/` | POST | dictation upload |

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

All four have since been fixed in REA+:

- `capture-browser-scenario` launch mode did not pass `HTTPS_PROXY` (or
  `HTTP_PROXY`/`NO_PROXY`) to the browser it starts. Behind this
  environment's TLS-inspecting proxy the load failed with
  `ERR_CERT_AUTHORITY_INVALID`. Connect mode, with a self-started
  Chromium, worked. *Fixed:* the proxy variables are now passed through.
- `list-browser-targets` listed only HTTP(S) pages, so a fresh browser on
  `about:blank` needed a page opened first. *Fixed:* blank tabs are listed
  with `origin: null`.
- `analyze-web-bundle` reported endpoints passed as literal strings but not
  template-literal paths. *Fixed:* templates, concatenation and paths held
  in a local variable are reported with `{}` for each expression. On the
  `_app` chunk, network endpoints went from 55 to 192 (108 templated).
- `analyze-javascript-application` gave three of the 12 chunks no semantic
  graph: the 4.5 MB `_app` chunk used up the shared result budget before
  `pages/index` and `webpack` were reached. *Fixed:* JavaScript sources are
  analyzed smallest first, and `--max-semantic-source-bytes` gives
  oversized bundles static facts only (2 min 50 s → 53 s here with a 1 MB
  limit).

## Documented API and MCP server (published by Consensus)

Consensus documents a machine interface for integrators. These facts come
from its own `https://docs.consensus.app/llms.txt` and
`https://consensus.app/llms-full.txt`, read on 2026-10-17. The individual
docs pages return a Cloudflare challenge to automated clients but open in an
ordinary browser.

- **REST API.** Bearer API key from an organization subscription
  (`/subscription/api`).
  - `GET /v1/search` returns ranked papers. The legacy
    `/v1/quick_search` is deprecated and will be removed on 2027-02-07.
  - Threads hand a question to the research agent, create-then-poll:
    - start a Thread to get a `thread_id`, then poll
      `GET /v1/threads/{thread_id}` until its status is `idle` (about every
      30 s, capped at 3 requests/s);
    - follow-ups return a new `interaction_id`, or 409 while the latest
      interaction is still running;
    - you can also list your earlier Threads.
  - Most endpoints allow 1 request/s. Over a limit you get 429 with
    `Retry-After`.
  - Full-text passages and papers per request depend on the plan.
- **MCP server** at `https://mcp.consensus.app/mcp`.
  - Tools: `search`, `create_thread`, `get_thread`, `add_to_thread`,
    `find_threads`.
  - Auth: OAuth 2.1 (authorization code with PKCE, dynamic client
    registration, discovery at
    `/.well-known/oauth-authorization-server`) or an API key.
  - An **anonymous tier** for evaluation returns 3 papers per search with
    reduced fields, under a shared rate limit.
  - The ChatGPT and Claude apps are thin wrappers over this server.
- **Stated corpus.** About 400M records (350M peer-reviewed), from Semantic
  Scholar, OpenAlex, PubMed and publisher feeds, updated weekly.

This matches the web client's private paths (`threads/{id}/interactions/{id}/...`,
`paper_search/`, `mcp_credits/`). The documented API is the sanctioned way
to see real request and response shapes; the private `/api/` paths stay
undocumented.
