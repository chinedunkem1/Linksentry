/**
 * Stripe billing — activates automatically when environment variables are set:
 *   STRIPE_SECRET_KEY      sk_live_... / sk_test_...
 *   STRIPE_PRICE_ID        price_... (recurring price for the Pro plan)
 *   STRIPE_WEBHOOK_SECRET  whsec_...  (from the webhook endpoint config)
 *   APP_URL                public base URL, e.g. https://linksentry.app
 *
 * Uses Stripe's REST API directly via fetch — no SDK dependency.
 * When unconfigured, checkout returns a friendly "waitlist" response so the
 * site works fine without a Stripe account.
 */

const crypto = require('crypto');
const db = require('./db');

const API = 'https://api.stripe.com/v1';

function isConfigured() {
  return Boolean(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_PRICE_ID);
}

function form(params) {
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) body.append(k, v);
  return body;
}

async function stripeRequest(path, params) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: form(params),
    signal: AbortSignal.timeout(15000),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || `Stripe error (${res.status})`);
  return data;
}

/** Creates a Stripe Checkout session for the Pro subscription. */
async function createCheckoutSession(user) {
  const appUrl = process.env.APP_URL || 'http://localhost:3000';
  return stripeRequest('/checkout/sessions', {
    mode: 'subscription',
    'line_items[0][price]': process.env.STRIPE_PRICE_ID,
    'line_items[0][quantity]': '1',
    customer_email: user.email,
    client_reference_id: String(user.id),
    success_url: `${appUrl}/dashboard?upgraded=1`,
    cancel_url: `${appUrl}/#pricing`,
  });
}

/** Verifies a Stripe-Signature header (v1 HMAC-SHA256 scheme). */
function verifyWebhookSignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;
  const parts = Object.fromEntries(
    signatureHeader.split(',').map((p) => p.split('=').map((s) => s.trim()))
  );
  const timestamp = parts.t;
  const signature = parts.v1;
  if (!timestamp || !signature) return false;
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false; // 5 min tolerance
  const expected = crypto.createHmac('sha256', secret)
    .update(`${timestamp}.${rawBody}`)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  } catch {
    return false;
  }
}

/** Handles checkout.session.completed / subscription cancellation events. */
function handleWebhookEvent(event) {
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = Number(session.client_reference_id);
    if (userId) {
      db.prepare(`UPDATE users SET plan = 'pro', stripe_customer_id = ? WHERE id = ?`)
        .run(session.customer || null, userId);
      return { handled: true, action: `user ${userId} upgraded to pro` };
    }
  }
  if (event.type === 'customer.subscription.deleted') {
    const customerId = event.data.object.customer;
    if (customerId) {
      db.prepare(`UPDATE users SET plan = 'free' WHERE stripe_customer_id = ?`).run(customerId);
      return { handled: true, action: `customer ${customerId} downgraded to free` };
    }
  }
  return { handled: false };
}

module.exports = { isConfigured, createCheckoutSession, verifyWebhookSignature, handleWebhookEvent };
