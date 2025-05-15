import * as openpgp from 'openpgp';

const secureHandler = (() => {
  const CONFIG = {
    appScriptUrl: 'https://script.google.com/macros/s/[YOUR_APPS_SCRIPT_ID]/exec',
    virusTotalApiKey: '[YOUR_VIRUSTOTAL_API_KEY]',
    recaptchaSiteKey: '[YOUR_RECAPTCHA_SITE_KEY]',
    maxFileSize: 5 * 1024 * 1024,
    allowedFileTypes: ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
  };

  const generateNonce = () => {
    const array = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
  };

  const sanitizeInput = (input) => {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML.replace(/[<>&"]/g, (m) => ({
      '<': '<',
      '>': '>',
      '&': '&',
      '"': '"'
    })[m]);
  };

  async function validateRecaptcha() {
    return new Promise((resolve, reject) => {
      grecaptcha.ready(() => {
        grecaptcha.execute(CONFIG.recaptchaSiteKey, { action: 'submit' })
          .then(token => fetch(CONFIG.appScriptUrl + '/verify-recaptcha', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
            body: JSON.stringify({ token })
          }))
          .then(res => res.json())
          .then(data => data.success ? resolve() : reject(new Error('reCAPTCHA verification failed')))
          .catch(reject);
      });
    });
  }

  async function sha256(arrayBuffer) {
    const hash = await crypto.subtle.digest('SHA-256', arrayBuffer);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function scanFile(file) {
    if (file.size > CONFIG.maxFileSize) throw new Error('File exceeds 5MB limit');
    if (!CONFIG.allowedFileTypes.includes(file.type)) throw new Error('Invalid file type');
    const form = new FormData();
    form.append('file', file);
    const res = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': CONFIG.virusTotalApiKey,
        'X-CSRF-Token': getCsrfToken()
      },
      body: form
    });
    if (!res.ok) throw new Error(`VirusTotal scan failed: ${res.statusText}`);
    const data = await res.json();
    const isClean = data.data.attributes.last_analysis_stats.malicious === 0;
    if (!isClean) throw new Error('File flagged as malicious');
    return { id: data.data.id, clean: isClean };
  }

  async function getPgpKey() {
    const res = await fetch(CONFIG.appScriptUrl + '/get-public-key', {
      method: 'GET',
      headers: { 'X-CSRF-Token': getCsrfToken() }
    });
    if (!res.ok) throw new Error('Failed to fetch PGP key');
    const { key, checksum } = await res.json();
    if (!key.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) throw new Error('Invalid key format');
    const computedChecksum = await sha256(new TextEncoder().encode(key));
    if (computedChecksum !== checksum) throw new Error('PGP key checksum mismatch');
    return key;
  }

  async function encryptPayload(meta, fileArrayBuffer) {
    const publicKey = await openpgp.readKey({ armoredKey: await getPgpKey() });
    const msg = await openpgp.createMessage({
      binary: fileArrayBuffer || new Uint8Array(),
      text: JSON.stringify(meta)
    });
    const encrypted = await openpgp.encrypt({
      message: msg,
      encryptionKeys: publicKey,
      format: 'binary'
    });
    return new Uint8Array(encrypted);
  }

  function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.content || '';
  }

  let lastRequest = 0;
  async function submitContact(event) {
    event.preventDefault();
    const form = event.target;
    const feedback = form.querySelector('.feedback') || document.createElement('div');
    feedback.className = 'feedback text-red-600 mt-2';
    form.appendChild(feedback);
    const now = Date.now();
    if (now - lastRequest < 1000) {
      feedback.textContent = 'Please wait before submitting again';
      return;
    }
    lastRequest = now;
    try {
      await validateRecaptcha();
      const fileInput = document.getElementById('contact-file');
      const file = fileInput.files[0];
      let fileBuf = new Uint8Array();
      let scan = { id: '', clean: true };
      if (file) {
        scan = await scanFile(file);
        fileBuf = await file.arrayBuffer();
      }
      const payloadMeta = {
        type: 'contact',
        name: sanitizeInput(document.getElementById('contact-name').value),
        email: sanitizeInput(document.getElementById('contact-email').value),
        message: sanitizeInput(document.getElementById('contact-msg').value),
        nonce: generateNonce(),
        timestamp: new Date().toISOString(),
        scanId: scan.id,
        sha256: file ? await sha256(fileBuf) : ''
      };
      const encryptedBlob = await encryptPayload(payloadMeta, fileBuf);
      await sendToServer(encryptedBlob, payloadMeta, feedback);
      feedback.className = 'feedback text-green-600 mt-2';
      feedback.textContent = 'Submission successful!';
      form.reset();
    } catch (err) {
      feedback.textContent = `Error: ${err.message}`;
    }
  }

  async function submitVuln(event) {
    event.preventDefault();
    const form = event.target;
    const feedback = form.querySelector('.feedback') || document.createElement('div');
    feedback.className = 'feedback text-red-600 mt-2';
    form.appendChild(feedback);
    const now = Date.now();
    if (now - lastRequest < 1000) {
      feedback.textContent = 'Please wait before submitting again';
      return;
    }
    lastRequest = now;
    try {
      await validateRecaptcha();
      const payloadMeta = {
        type: 'security',
        reporter: sanitizeInput(document.getElementById('vuln-name').value),
        details: sanitizeInput(document.getElementById('vuln-details').value),
        nonce: generateNonce(),
        timestamp: new Date().toISOString()
      };
      const encrypted = await encryptPayload(payloadMeta, new Uint8Array());
      await sendToServer(encrypted, payloadMeta, feedback);
      feedback.className = 'feedback text-green-600 mt-2';
      feedback.textContent = 'Submission successful!';
      form.reset();
    } catch (err) {
      feedback.textContent = `Error: ${err.message}`;
    }
  }

  async function sendToServer(encryptedBlob, meta, feedback) {
    const body = new FormData();
    body.append('meta', JSON.stringify(meta));
    body.append('encrypted', new Blob([encryptedBlob]));
    body.append('recaptchaToken', await grecaptcha.execute(CONFIG.recaptchaSiteKey, { action: 'submit' }));
    body.append('csrfToken', getCsrfToken());
    const res = await fetch(CONFIG.appScriptUrl, {
      method: 'POST',
      headers: { 'X-CSRF-Token': getCsrfToken() },
      body
    });
    if (!res.ok) throw new Error(`Server error: ${res.statusText}`);
    const txt = await res.text();
    if (txt.includes('<')) throw new Error('Invalid response from server');
    feedback.textContent = txt;
  }

  function init() {
    const securityForm = document.getElementById('securityForm');
    const contactForm = document.getElementById('contactForm');
    if (securityForm) securityForm.addEventListener('submit', submitVuln);
    if (contactForm) contactForm.addEventListener('submit', submitContact);
  }

  document.addEventListener('DOMContentLoaded', init);

  return { submitContact, submitVuln };
})();
