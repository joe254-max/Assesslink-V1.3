# Deployment Guide: KNPSS Link on Render

This guide outlines the deployment architecture and steps required to run **KNPSS Link** (AssessLink) on Render.

## 1. Two-Service Architecture on Render

The application utilizes a decoupled full-stack architecture with a main web service and an asynchronous queue-based background worker. Both services are defined in the `render.yaml` blueprint file at the root of the project.

### Web Service (`knpss-link`)
- **Type**: Web Service
- **Build Command**: `npm run build`
- **Start Command**: `npm start`
- **Function**: Serves the React SPA frontend and proxies API queries, database interactions, and SMS/USSD routing.

### Background Worker (`knpss-worker`)
- **Type**: Background Worker
- **Build Command**: `npm run build`
- **Start Command**: `node dist/worker.cjs`
- **Function**: Processes asynchronous jobs, background SMS dispatches, automated reminder cycles, and logbook validation queues using BullMQ and Redis.

---

## 2. Environment Variables Configuration

Both services require the following environment variables. Set these as **Sync: false** (user-supplied) during Render service setup:

| Variable Name | Description / Value |
| :--- | :--- |
| `SUPABASE_URL` | Your Supabase project URL (`https://xxxx.supabase.co`). |
| `SUPABASE_SERVICE_ROLE_KEY` | Service role key used for administrative database queries. |
| `SUPABASE_ANON_KEY` | Public anonymous key for client interactions. |
| `VITE_SUPABASE_URL` | Client-side copy of the Supabase project URL (must match `SUPABASE_URL`). |
| `VITE_SUPABASE_ANON_KEY` | Client-side copy of the anonymous key (must match `SUPABASE_ANON_KEY`). |
| `REDIS_URL` | Redis connection string (`redis://...`) required by BullMQ. |
| `TERMII_API_KEY` | API Key for Termii SMS and OTP verification. |
| `TERMII_SENDER_ID` | Sender ID registered with Termii. |
| `TERMII_BASE_URL` | Base API URL for Termii endpoints. |
| `ALLOWED_ORIGINS` | Comma-separated list of allowed origins (e.g., `https://knpss-link.onrender.com`). |
| `APP_URL` | The external canonical URL of your deployed web service. |

---

## 3. Required Supabase Infrastructure Setup

Before running the application, ensure the database schema is configured and the necessary storage infrastructure is provisioned:

### Step 3.1: Execute Schema SQL
Apply the schema files in order in your Supabase SQL Editor:
1. `supabase/001_schema.sql` (Tables, types, and triggers)
2. `supabase/002_rls_policies.sql` (Security & access control)
3. `supabase/004_indexes.sql` / `005_indexes.sql` (Performance optimizations & realtime publications)

### Step 3.2: Create the Storage Bucket
The application relies on Supabase Storage for managing student portfolio uploads, letters of acceptance, and field evidence files.
- **Bucket Name**: `assesslink-uploads`
- **Privacy Level**: **Private** (authenticated/authorized retrieval only)
- **Steps**:
  1. Go to **Supabase Dashboard** → **Storage**.
  2. Click **New Bucket**.
  3. Enter the name: `assesslink-uploads`.
  4. Ensure the toggle for **Public bucket** is turned **OFF** (Private).
  5. Click **Create bucket**.

---

## 4. Post-Deployment Auth User Creation

The initial migration scripts and database imports populate the `users` and role profile tables (`trainee_profiles`, `officer_profiles`, `supervisor_profiles`, `admin_profiles`), but **do not** automatically create Supabase Auth accounts. 

To enable login for imported or pre-existing users, match their emails/phones with active Auth identities:

### Options for Auth Creation:
- **Option A (Manual Invite)**:
  Use **Supabase Dashboard** → **Authentication** → **Invite user** to send invitation links one by one. This is recommended for administrators and placement officers.
  
- **Option B (Admin API Bulk Creation)**:
  Write a script using the Supabase Admin API (`supabase.auth.admin.createUser`) to programmatic bulk-provision Auth identities with temporary passwords. For trainees, map phone numbers or temporary passwords for reliable entry.

- **Option C (Self-Registration / OTP Magic Links)**:
  Configure the login workflow to allow self-registration or magic link OTP validation on first access, allowing users to claim their pre-existing profiles using their registered email or phone numbers.
