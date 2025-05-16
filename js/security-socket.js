// security-socket.js
// Purpose: Frontend logic for OPS Security Disclosure Form
// - Handles form submission
// - Validates inputs (file size/type, fields)
// - Connects via WebSocket to FastAPI for malware scan
// - If clean: encrypts data, sends to Apps Script for secure storage
// - Shows real-time status to the user

// CONFIG (replace with your real endpoints/keys)
const FASTAPI_WS_URL = "wss://YOUR_FASTAPI_BACKEND/secure/ws";
const APPS_SCRIPT_URL = "https://script.google.com/macros/s/YOUR_APPS_SCRIPT_ID/exec";
const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("security-form");
  const statusBox = document.getElementById("status");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    statusBox.textContent = "Validating inputs...";

    // Gather form data
    const reporter = form.reporter.value.trim();
    const details = form.details.value.trim();
    const fileInput = form.attachment;
    const file = fileInput.files[0];

    // Basic validation
    if (!reporter || !details) {
      statusBox.textContent = "All fields are required.";
      return;
    }
    if (!file || !["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"].includes(file.type)) {
      statusBox.textContent = "Please upload a valid PDF or DOC/DOCX file.";
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      statusBox.textContent = "File exceeds 25MB limit.";
      return;
    }

    // Connect to FastAPI WebSocket
    statusBox.textContent = "Connecting for malware scan...";
    const ws = new WebSocket(FASTAPI_WS_URL);

    ws.onopen = () => {
      statusBox.textContent = "Uploading file for malware scan...";
      // Send metadata and file as ArrayBuffer
      ws.send(JSON.stringify({ reporter, details, filename: file.name, type: file.type, size: file.size }));

      // Read file as ArrayBuffer
      const reader = new FileReader();
      reader.onload = (evt) => {
        ws.send(evt.target.result);
      };
      reader.readAsArrayBuffer(file);
    };

    ws.onmessage = async (event) => {
      const resp = JSON.parse(event.data);
      if (resp.status === "scanning") {
        statusBox.textContent = "Scanning file for malware...";
      } else if (resp.status === "clean") {
        statusBox.textContent = "File is clean. Encrypting and uploading...";
        // --- Encryption Logic Here (simplified: you would use WebCrypto/OpenPGP) ---
        const encryptedPayload = await encryptSubmission({ reporter, details, file }); // Placeholder for your encrypt function
        // Send encrypted payload to Apps Script
        const uploadResp = await fetch(APPS_SCRIPT_URL, {
          method: "POST",
          body: encryptedPayload,
          headers: { "Content-Type": "application/octet-stream" }
        });
        if (uploadResp.ok) {
          statusBox.textContent = "Submission received securely. Thank you!";
        } else {
          statusBox.textContent = "Failed to upload to secure backend.";
        }
        ws.close();
      } else if (resp.status === "infected") {
        statusBox.textContent = "Malware detected in file. Submission blocked.";
        ws.close();
      } else {
        statusBox.textContent = "Unexpected response from server.";
        ws.close();
      }
    };

    ws.onerror = (err) => {
      statusBox.textContent = "WebSocket error: " + err.message;
    };
    ws.onclose = () => {
      // Optionally: clear any loading state
    };
  });
});

// --- Placeholder for encryption logic (implement with WebCrypto/OpenPGP.js) ---
async function encryptSubmission({ reporter, details, file }) {
  // TODO: Implement actual RSA-OAEP/AES-GCM encryption here
  // For demo: just bundle as JSON Blob (not secure, replace in production!)
  const obj = { reporter, details, filename: file.name, filedata: await file.arrayBuffer() };
  return new Blob([JSON.stringify(obj)]);
}
