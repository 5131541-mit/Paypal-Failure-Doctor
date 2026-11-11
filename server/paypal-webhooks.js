const sandboxApi = 'https://api-m.sandbox.paypal.com';

export function summarizeWebhookEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return null;
  const id = typeof event.id === 'string' ? event.id.slice(0, 255) : '';
  const type = typeof event.event_type === 'string' ? event.event_type.slice(0, 160) : '';
  if (!id || !type) return null;
  const resource = event.resource && typeof event.resource === 'object' ? event.resource : {};
  const relatedOrder = resource.supplementary_data?.related_ids?.order_id;
  const orderId = typeof relatedOrder === 'string' ? relatedOrder : (type.startsWith('CHECKOUT.ORDER.') && typeof resource.id === 'string' ? resource.id : null);
  return {
    id,
    type,
    orderId: orderId?.slice(0, 255) || null,
    resourceId: typeof resource.id === 'string' ? resource.id.slice(0, 255) : null,
    status: typeof resource.status === 'string' ? resource.status.slice(0, 80) : null,
  };
}

export async function verifyPayPalWebhook(event, headers, { webhookId, accessToken, apiBase = sandboxApi, fetchImpl = fetch }) {
  const transmission = {
    auth_algo: headers['paypal-auth-algo'],
    cert_url: headers['paypal-cert-url'],
    transmission_id: headers['paypal-transmission-id'],
    transmission_sig: headers['paypal-transmission-sig'],
    transmission_time: headers['paypal-transmission-time'],
  };
  if (!webhookId || !accessToken || Object.values(transmission).some((value) => typeof value !== 'string' || !value)) return false;
  const response = await fetchImpl(`${apiBase}/v1/notifications/verify-webhook-signature`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...transmission, webhook_id: webhookId, webhook_event: event }),
    signal: AbortSignal.timeout(8_000),
  });
  if (!response.ok) return false;
  const result = await response.json();
  return result.verification_status === 'SUCCESS';
}
