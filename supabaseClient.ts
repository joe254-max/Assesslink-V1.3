/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Supabase client for server-side use only. This uses the SERVICE ROLE key,
 * which bypasses Row Level Security — that's correct here because the
 * Express server is the trusted backend; RLS (002_rls_policies.sql) exists
 * as a safety net for any future direct client-to-Supabase calls.
 *
 * NEVER import this file or expose SUPABASE_SERVICE_ROLE_KEY in any
 * frontend/browser code.
 */
import dotenv from 'dotenv';
dotenv.config({ override: true });

import { createClient, SupabaseClient } from '@supabase/supabase-js';

let cachedClient: SupabaseClient | null = null;

function getSupabaseClient(): SupabaseClient {
  if (!cachedClient) {
    const clean = (val: string | undefined) => val ? val.replace(/^["']|["']$/g, '').trim() : '';
    const url = clean(process.env.SUPABASE_URL);
    const key = clean(process.env.SUPABASE_SERVICE_ROLE_KEY);
    if (!url || !key) {
      throw new Error(
        'Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables. ' +
        'Please configure your Supabase credentials (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY) ' +
        'in the AI Studio Settings (Secrets) panel to connect to your database.'
      );
    }
    cachedClient = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return cachedClient;
}

// Export a proxy that behaves exactly like the Supabase client but loads/initializes it lazily
export const supabase = new Proxy({} as SupabaseClient, {
  get(target, prop, receiver) {
    const client = getSupabaseClient();
    const value = Reflect.get(client, prop);
    if (typeof value === 'function') {
      return value.bind(client);
    }
    return value;
  }
});

// Storage bucket used by the generic /api/v1/upload endpoint.
// Create this bucket (private) in Supabase Storage before deploying.
export const UPLOADS_BUCKET = 'assesslink-uploads';
