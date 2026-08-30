# Arthur Rai availability broker operating rules

Apply the parent CloudTMS workspace `AGENTS.md` in full.

- `broker` is the LIVE `arthur-rai-broker` Worker and publishes the Availability integration at `availability.arthur-rai.co.uk`.
- LIVE database traffic must use `https://cloudtms-live-miget-gateway.kier-88a.workers.dev`. The `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` names are compatibility names only; their effective values must be the independently credentialed LIVE Miget/PostgREST gateway and matching LIVE service-role JWT.
- Preserve the `global_fetch_strictly_public` compatibility flag. Without it, a Worker-to-Worker request to the public LIVE gateway fails with Cloudflare error `1042`, including the scheduled Sheets outbox retry.
- Never route this Worker to either former Supabase project, TEST Miget, the MyTMS control plane, or another agency credential.
- Preserve the existing R2 binding, Google webhook secrets/settings and the five-minute cron unless the user explicitly authorises an exact change.
- Deploy from repository `kierarthur/timesheets`, branch `main`, root `broker`, using `npx wrangler deploy --keep-vars`. An exact-version upload with an ephemeral ignored secrets file is permitted when a URL and matching secret must change atomically; delete the file immediately after upload.
- After deployment, prove `/healthz`, the effective database hostname, the active version at 100%, one read-only LIVE Miget request, and a normal five-minute scheduled invocation with no exceptions. Do not trigger uploads, sheet writes or application-data mutations merely for verification.
- Never print, commit, copy into documentation or expose the service-role JWT, HMAC secret, upload token, webhook credential or any other secret value.
