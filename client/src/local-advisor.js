const adviceByScenario = {
  INSTRUMENT_DECLINED: {
    diagnosis: 'The checkout treats a declined funding source like a successful payment. That can mark an unpaid order as fulfilled.',
    patch: 'Branch on INSTRUMENT_DECLINED, return a recoverable response to the browser, and let the buyer restart checkout with another funding source.',
    verification: 'A decline must leave fulfillment disabled. The UI should offer a retry path and must never show “Payment complete.”',
  },
  DUPLICATE_INVOICE_ID: {
    diagnosis: 'The same invoice identifier is being reused. PayPal can reject the request, and a blind retry may repeat the same failure.',
    patch: 'Generate a stable unique invoice ID per logical purchase and use a PayPal-Request-Id idempotency key for safe retries.',
    verification: 'A repeated request should resolve to the same logical order or a clear duplicate response, never a second fulfillment.',
  },
  INTERNAL_SERVER_ERROR: {
    diagnosis: 'The capture result is uncertain after a transient server failure. Immediately capturing again can create an unsafe retry path.',
    patch: 'Fetch the order status before retrying. Retry only when the payment is known not to have completed, using a stable request ID.',
    verification: 'The app must not fulfill on an unknown response. A retry should first reconcile order status and should not create duplicate fulfillment.',
  },
};

export function getLocalAdvice(scenario, trace = '') {
  const advice = adviceByScenario[scenario];
  if (!advice) return null;

  return {
    ...advice,
    evidence: trace,
    model: 'Browser-local recovery advisor',
    source: 'local',
  };
}
