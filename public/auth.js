/**
 * Shared sign-in / sign-up form handling.
 * The form's `data-endpoint` attribute selects which API it posts to.
 */
(() => {
  const form = document.getElementById('auth-form');
  if (!form) return;

  const errBox = document.getElementById('form-error');
  const btn = document.getElementById('submit-btn');
  const endpoint = form.dataset.endpoint;
  const busyLabel = form.dataset.busyLabel || 'Working…';
  const idleLabel = btn.textContent;

  /* Bot check: the server issues a signed, time-limited token when the page
     loads and requires it back on submit. */
  let formToken = '';
  async function fetchToken() {
    try {
      const res = await fetch('/api/form-token');
      if (!res.ok) return false;
      const data = await res.json();
      formToken = data.token || '';
      return Boolean(formToken);
    } catch {
      return false;
    }
  }
  fetchToken();

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    btn.disabled = true;
    btn.textContent = busyLabel;
    errBox.hidden = true;

    try {
      // If the token never arrived (offline, throttled), try once more now
      // rather than failing the submit with a confusing message.
      if (!formToken) await fetchToken();

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: document.getElementById('email').value,
          password: document.getElementById('password').value,
          website: document.getElementById('website').value, // honeypot
          formToken,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Something went wrong.');
      location.href = '/dashboard';
    } catch (err) {
      errBox.textContent = err.message;
      errBox.hidden = false;
      btn.disabled = false;
      btn.textContent = idleLabel;
    }
  });
})();
