// ============================================================================
// ASSESSLINK / KNPSS Link — Decoupled Job Worker Process
// processes BullMQ background jobs for SMS and Notifications via Termii
// ============================================================================

import dotenv from 'dotenv';
dotenv.config();

import { Worker } from 'bullmq';
import { supabase } from './supabaseClient'; // Server service role client
import { computeRiskFlags } from './riskFlags';

const REDIS_URL = process.env.REDIS_URL;

console.log('--- starting ASSESSLINK / KNPSS Link Background Worker ---');

if (!REDIS_URL) {
  console.log('No REDIS_URL configured. Background worker will not boot as BullMQ relies on Redis.');
  console.log('Ensure process.env.REDIS_URL is configured for multi-dyno background queue scaling.');
  process.exit(0);
}

// Phone number normalization to international digits only (e.g. 254712345678) for Termii APIs
function normalizePhoneNumber(phone: string): string {
  let cleaned = phone.replace(/[^0-9]/g, ''); // strip everything except digits
  if (phone.startsWith('+')) {
    return phone.replace('+', '');
  }
  if (phone.startsWith('0')) {
    return '254' + phone.slice(1);
  }
  if (phone.startsWith('254') && cleaned.length >= 9) {
    return cleaned;
  }
  if (cleaned.length === 9) {
    return '254' + cleaned;
  }
  return cleaned;
}

// Cache helper equivalent inside worker process
async function getSystemSettings() {
  const { data, error } = await supabase
    .from('system_settings')
    .select('*')
    .eq('id', true)
    .single();
  if (error) {
    console.error('getSystemSettings error:', error.message);
    return null;
  }
  return data;
}

// ----------------------------------------------------------------------------
// Swappable SMS Provider Architecture - configured for Termii
// ----------------------------------------------------------------------------
interface SMSProvider {
  send(phone: string, message: string): Promise<{ success: boolean; messageId?: string; error?: string }>;
}

async function sendTermiiSMS(phone: string, message: string): Promise<{ success: boolean; messageId?: string; error?: string }> {
  const apiKey = process.env.TERMII_API_KEY;
  const senderId = process.env.TERMII_SENDER_ID || 'KNPSS_LINK';
  const baseUrl = process.env.TERMII_BASE_URL || 'https://api.ng.termii.com';
  
  const normalizedPhone = normalizePhoneNumber(phone);
  try {
    const response = await fetch(`${baseUrl}/api/sms/send`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        api_key: apiKey,
        to: normalizedPhone,
        from: senderId,
        sms: message,
        type: "plain",
        channel: "generic"
      })
    });
    const data = await response.json() as any;
    if (response.ok && (data.message === "Successfully Sent" || data.status === "success" || data.messageId || data.message_id)) {
      return { success: true, messageId: data.messageId || data.message_id || "termii_ok" };
    } else {
      return { success: false, error: data.message || JSON.stringify(data) };
    }
  } catch (err: any) {
    return { success: false, error: err.message || String(err) };
  }
}

class TermiiSMSProvider implements SMSProvider {
  async send(phone: string, message: string) {
    return sendTermiiSMS(phone, message);
  }
}

let smsProvider: SMSProvider | null = null;
if (process.env.TERMII_API_KEY) {
  smsProvider = new TermiiSMSProvider();
  console.log("✓ Termii SMS Production Provider active in Worker.");
} else {
  console.warn("⚠️ Termii SMS credentials (TERMII_API_KEY) missing. Background worker falling back to simulation sandbox.");
}

// ----------------------------------------------------------------------------
// 1. SMS worker
// ----------------------------------------------------------------------------
const smsWorker = new Worker('sms', async (job) => {
  const { phone, message } = job.data;
  console.log(`[Worker - SMS] Processing active job for destination: ${phone}`);

  const settings = await getSystemSettings();
  const senderId = settings?.sms_sender_id || 'KNPSS_LINK';

  const normalizedPhone = normalizePhoneNumber(phone);

  if (smsProvider) {
    const res = await smsProvider.send(phone, message);
    if (res.success) {
      await supabase.from('sms_logs').insert({
        phone_number: normalizedPhone,
        message,
        sender_id: senderId,
        status: 'SENT'
      });
      console.log(`[Success] Real SMS sent via Termii. MessageID: ${res.messageId}`);
    } else {
      await supabase.from('sms_logs').insert({
        phone_number: normalizedPhone,
        message,
        sender_id: senderId,
        status: 'FAILED'
      });
      console.warn(`[Failed] Real SMS delivery error: ${res.error}`);
    }
  } else {
    // Save to Postgres logs
    await supabase.from('sms_logs').insert({
      phone_number: normalizedPhone,
      message,
      sender_id: senderId,
      status: 'SENT'
    });
    console.log(`[Simulate] SMS routed: Phone=${normalizedPhone}, Msg="${message}"`);
  }
}, { connection: { url: REDIS_URL } });

// ----------------------------------------------------------------------------
// 2. Notifications worker
// ----------------------------------------------------------------------------
const notifWorker = new Worker('notifications', async (job) => {
  const { userId, type, title, body, entType, entId } = job.data;
  console.log(`[Worker - Notifications] Enforcing app_notifications delivery for user_id: ${userId}`);

  const { error } = await supabase.from('app_notifications').insert({
    user_id: userId,
    type,
    title,
    body,
    is_read: false,
    related_entity_type: entType ?? null,
    related_entity_id: entId ?? null,
  });

  if (error) {
    console.error(`[Error] Worker failed app_notification insert: ${error.message}`);
  }
}, { connection: { url: REDIS_URL } });

// ----------------------------------------------------------------------------
// 3. Risk Flagging worker
// ----------------------------------------------------------------------------
const riskFlaggingWorker = new Worker('riskFlagging', async (job) => {
  console.log(`[Worker - RiskFlagging] Starting active job for: ${job.name}`);
  const result = await computeRiskFlags();
  console.log(`[Worker - RiskFlagging] Job ${job.name} finished. Newly created flags count: ${result}`);
}, { connection: { url: REDIS_URL } });

smsWorker.on('error', err => console.error('SMS Worker general error:', err));
notifWorker.on('error', err => console.error('Notification Worker general error:', err));
riskFlaggingWorker.on('error', err => console.error('RiskFlagging Worker general error:', err));

console.log('✓ Workers actively bound to Redis channels. Worker process waiting for incoming requests.');
