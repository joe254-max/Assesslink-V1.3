# ASSESSLINK / KNPSS Link

An Industrial Attachment Management system.

## Realtime Delivery & Scaled Background Processing (Scale Upgrades)

To handle thousands of concurrent students, supervisors, and officers seamlessly, the application has been upgraded with a high-scale reactive and asynchronous architecture:

1. **Live Subscriptions (Supabase Realtime)**:
   - Polling has been completely eliminated on the frontend application layers. 
   - Live tables are bound via PostgreSQL Replication publications to Supabase Realtime:
     - `app_notifications`: Real-time desktop alerts and badging the instant a notification occurs.
     - `logbook_entries`: Real-time state synchronization when officers reject/approve submissions.
     - `assessments`: Infinite live updates on assessments and field visits.
     - `attendance_records`: Officers see realtime attendance modifications and sign-ins live.

2. **Background Job Queues (BullMQ & Redis)**:
   - Slow external interactions (e.g. Africa's Talking SMS dispatch, Safaricom Daraja STK Push callbacks) are offloaded onto thread-safe background queues.
   - **Scale Mode**: Configured by specifying `REDIS_URL` which sets up BullMQ queues (`sms`, `notifications`, `mpesa-callbacks`) and handles jobs asynchronously.
   - **Simulate/Inline Mode**: If no `REDIS_URL` is set, the applet gracefully falls back to inline/synchronous processing to sustain local sandbox testing.
   - In production, spin up `worker.ts` alongside your web service:
     ```bash
     # Start production background workers
     node dist/worker.cjs
     ```

3. **In-Memory TTL Caching**:
   - Frequently-read and rarely changing records like `system_settings` and `institutional_documents` utilize a thread-safe `SimpleCache` with a 60-second Time To Live (TTL).
   - Cache is automatically invalidated the instant a write occurs (`POST /api/v1/system/settings`, `POST /api/v1/documents`).

4. **Direct Storage Redirects**:
   - Node server process no longer buffers or proxies file download bytes.
   - File requests are resolved with a short-lived (15 minutes) signed Supabase storage URL redirect, freeing up CPU and network I/O.

## Security Controls & Policies

- **Role-Based Access Control**: Highly refined middleware securing all protected endpoints based on verified application roles (`TRAINEE`, `OFFICER`, `SUPERVISOR`, `ADMIN`).
- **Input & Storage Filtering**: Real-time ownership validation on placements and logbook entry fetches to prevent horizontal privilege escalation.
- **Strict Rate Limiting**: Limiters added on vital authentication endpoints.
- **Robust File Validation**: 10MB limits, magic-byte sniffing on uploads, explicit mime allowlists, attachment content disposition override on active media, and rigorous ownership access checks per file download.

## Mentoring Tool Data — Seeding Order (IMPORTANT)

Only `supabase/run_validated_seed.ts` (which reads `supabase/validated_seed.sql`) contains data sourced from the real KNP paper mentoring tools. The other two scripts in this folder (`seed_SYNTHETIC_comprehensive_templates.ts`, `seed_SYNTHETIC_dynamic_mentoring_tools.ts`) generate placeholder/fabricated content and should only ever be used for local development against an empty database — never against production.

Correct order for a fresh environment:
1. Run `001_schema.sql` through the latest numbered migration.
2. Manually create `mentoring_templates` rows for each real programme (department, programme, level, programme_code) — this is not yet automated; validated_seed.sql assumes templates already exist.
3. Run `npm run audit:mentoring-data` — expect near-100% "PLACEHOLDER" until templates + validated_seed.sql are both in place.
4. Run `tsx supabase/run_validated_seed.ts` to populate real units and elements against those templates.
5. Re-run `npm run audit:mentoring-data` to confirm PLACEHOLDER/SYNTHETIC_GENERATED counts only reflect genuinely missing rubric text, not accidental synthetic overwrites.

> [!CAUTION]
> Rotate `SUPABASE_SERVICE_ROLE_KEY` immediately if it has ever been committed, zipped, or shared outside a secrets manager.
