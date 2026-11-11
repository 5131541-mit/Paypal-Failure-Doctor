import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeWebhookEvent, verifyPayPalWebhook } from './paypal-webhooks.js';

const headers = {
  'paypal-auth-algo': 'SHA256withRSA',
  'paypal-cert-url': 'https://api-m.paypal.com/cert',
  'paypal-transmission-id': 'transmission-id',
  'paypal-transmission-sig': 'signature',
  'paypal-transmission-time': '2026-01-01T00:00:00Z',
};

test('webhook summary extracts order linkage and excludes unneeded buyer data', () => {
  const summary = summarizeWebhookEvent({ id: 'evt-1', event_type: 'PAYMENT.CAPTURE.COMPLETED', resource: { id: 'capture-1', status: 'COMPLETED', supplementary_data: { related_ids: { order_id: 'order-1' } }, payer: { email_address: 'private@example.test' } } });
  assert.deepEqual(summary, { id: 'evt-1', type: 'PAYMENT.CAPTURE.COMPLETED', orderId: 'order-1', resourceId: 'capture-1', status: 'COMPLETED' });
  assert.equal(summarizeWebhookEvent({ id: 'evt-2' }), null);
});

test('webhook verification sends PayPal required headers and returns success only for SUCCESS', async () => {
  let request;
  const fetchImpl = async (url, options) => {
    request = { url, options };
    return { ok: true, json: async () => ({ verification_status: 'SUCCESS' }) };
  };
  const event = { id: 'evt-3', event_type: 'CHECKOUT.ORDER.APPROVED', resource: { id: 'order-3' } };
  assert.equal(await verifyPayPalWebhook(event, headers, { webhookId: 'webhook-id', accessToken: 'token', fetchImpl }), true);
  assert.equal(request.url, 'https://api-m.sandbox.paypal.com/v1/notifications/verify-webhook-signature');
  assert.equal(request.options.headers.Authorization, 'Bearer token');
  assert.deepEqual(JSON.parse(request.options.body), {
    auth_algo: headers['paypal-auth-algo'], cert_url: headers['paypal-cert-url'], transmission_id: headers['paypal-transmission-id'],
    transmission_sig: headers['paypal-transmission-sig'], transmission_time: headers['paypal-transmission-time'],
    webhook_id: 'webhook-id', webhook_event: event,
  });
  assert.equal(await verifyPayPalWebhook(event, headers, { webhookId: 'webhook-id', accessToken: 'token', fetchImpl: async () => ({ ok: true, json: async () => ({ verification_status: 'FAILURE' }) }) }), false);
  assert.equal(await verifyPayPalWebhook(event, {}, { webhookId: 'webhook-id', accessToken: 'token', fetchImpl }), false);
});
