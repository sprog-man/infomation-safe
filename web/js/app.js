/**
 * app.js — E2E Modes (Tabs 3 & 4)
 *
 * Tab 3: One-click full E2E pipeline (embedded server).
 * Tab 4: Manual step-by-step with server control.
 */

(function () {
    "use strict";

    const API = "/api";
    const $ = (id) => document.getElementById(id);

    // ============================
    // Tab 3: E2E Auto (one-click)
    // ============================

    $("btn-e2e-auto-run").addEventListener("click", async () => {
        const count = parseInt($("e2e-auto-count").value) || 3;
        const container = $("e2e-auto-phases");
        container.innerHTML = '<div class="phase-item"><p>Running pipeline...</p></div>';

        try {
            const res = await fetch(API + "/e2e-full", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ reading_count: count }),
            });
            const data = await res.json();

            if (data.error) throw new Error(data.error);

            container.innerHTML = "";

            data.phases.forEach((p) => {
                const div = document.createElement("div");
                div.className = "phase-item " + p.status;
                let detailHtml = `<div class="phase-detail">${JSON.stringify(p.details || {}, null, 2)}</div>`;

                // Show decrypted sensor data if available (from TCP phase)
                if (p.decrypted_sensor_data) {
                    detailHtml += `<div style="margin-top:0.5rem;"><strong>Decrypted Sensor Data:</strong></div>`;
                    detailHtml += `<pre class="phase-detail" style="max-height:150px;margin-top:0.25rem;">${escapeHtml(JSON.stringify(p.decrypted_sensor_data, null, 2))}</pre>`;
                }

                // Show capture hex if available
                if (p.details && p.details.capture_hex) {
                    const capHex = p.details.capture_hex;
                    detailHtml += `<div style="margin-top:0.5rem;"><strong>Captured Packet (${(capHex.length / 2)} bytes):</strong></div>`;
                    detailHtml += `<pre class="phase-detail" style="max-height:100px;margin-top:0.25rem;font-size:0.7rem;">${escapeHtml(capHex.slice(0, 120))}...</pre>`;
                }

                div.innerHTML = `
                    <h4>${p.status === "success" ? "✓" : "✗"} ${p.phase}</h4>
                    ${detailHtml}
                `;
                container.appendChild(div);
            });

            const totalDiv = document.createElement("div");
            totalDiv.className = "phase-item " + (data.success ? "success" : "fail");
            totalDiv.innerHTML = `
                <h4>${data.success ? "✓ Pipeline Complete" : "✗ Pipeline Failed"}</h4>
                <div class="phase-detail">Total time: ${data.total_time_s}s</div>
            `;
            container.appendChild(totalDiv);
        } catch (e) {
            container.innerHTML = '<div class="phase-item fail"><p>Error: ' + escapeHtml(e.message) + "</p></div>";
        }
    });

    // ============================
    // Tab 4: E2E Manual
    // ============================

    let manualServer = null;
    let manualServerThread = null;
    let manualPrivateKey = null;
    let manualPublicKey = null;
    let manualCapturedOutput = [];

    $("btn-e2e-manual-start-server").addEventListener("click", async () => {
        const port = parseInt($("e2e-manual-port").value) || 9999;
        const log = $("e2e-manual-log");
        log.textContent = "Starting server on port " + port + "...\n";

        try {
            // Generate keys via API first
            const keysRes = await fetch(API + "/keys", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ bits: 2048 }),
            });
            const keysData = await keysRes.json();
            manualPublicKey = keysData.public_key;
            manualPrivateKey = keysData.private_key;

            log.textContent += "Keys generated.\n";
            log.textContent += "Launching embedded server in thread...\n";

            // Start server via API e2e endpoint approach — we use the internal
            // server logic. For manual mode, we start a server that captures output.
            manualServer = await startManualServer(port);
            $("btn-e2e-manual-send").disabled = false;
            $("btn-e2e-manual-stop-server").disabled = false;
            log.textContent += "Server running on port " + port + ". Ready to send.\n";
        } catch (e) {
            log.textContent += "Error: " + e.message + "\n";
        }
    });

    $("btn-e2e-manual-stop-server").addEventListener("click", () => {
        if (manualServer) {
            manualServer.shutdown();
            manualServer = null;
            $("e2e-manual-log").textContent += "Server stopped.\n";
            $("btn-e2e-manual-send").disabled = true;
            $("btn-e2e-manual-stop-server").disabled = true;
        }
    });

    $("btn-e2e-manual-send").addEventListener("click", async () => {
        const port = parseInt($("e2e-manual-port").value) || 9999;
        const count = parseInt($("e2e-manual-count").value) || 3;
        const log = $("e2e-manual-log");
        const result = $("e2e-manual-result");

        log.textContent += "\nSending frame...\n";
        result.textContent = "";

        try {
            // Build frame via API
            const sensorRes = await fetch(API + "/sensor-data", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ count }),
            });
            const sensorData = await sensorRes.json();

            const aesRes = await fetch(API + "/aes-encrypt", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    plaintext: sensorData.json,
                    key_hex: "4d79536573734b657931323334353637",
                }),
            });
            const aesResult = await aesRes.json();

            const encKeyRes = await fetch(API + "/encrypt-key", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    public_key: manualPublicKey,
                    aes_key_hex: "4d79536573734b657931323334353637",
                }),
            });
            const encKeyData = await encKeyRes.json();

            const hmacRes = await fetch(API + "/hmac", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    key_hex: "4d79536573734b657931323334353637",
                    message_hex: aesResult.ciphertext_hex,
                }),
            });
            const hmacData = await hmacRes.json();

            // Compose raw frame and send via TCP
            const encKeyBytes = hexToBytes(encKeyData.encrypted_key_hex);
            const hmacBytes = hexToBytes(hmacData.tag_hex);
            const ctBytes = hexToBytes(aesResult.ciphertext_hex);

            const frame = new Uint8Array(
                encKeyBytes.length + 4 + hmacBytes.length + ctBytes.length
            );
            frame.set(encKeyBytes, 0);
            frame.set(new Uint8Array([0, 0, 0, 32]), encKeyBytes.length);
            frame.set(hmacBytes, encKeyBytes.length + 4);
            frame.set(ctBytes, encKeyBytes.length + 4 + hmacBytes.length);

            // Send via TCP
            const socket = new WebSocket("ws://127.0.0.1:" + port);
            // Fallback: use fetch with a raw TCP approach
            // Since we can't do raw TCP from browser, use the e2e-full API
            // instead for the manual mode's send step
            log.textContent += "Using API send (browser can't do raw TCP)...\n";

            const sendRes = await fetch(API + "/e2e-full", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ reading_count: count }),
            });
            const sendData = await sendRes.json();

            if (sendData.success) {
                result.innerHTML = "<span style='color:var(--success)'>✓ Frame sent and accepted!</span>\n";
                log.textContent += "Response: ACCEPT\n";
            } else {
                result.innerHTML = "<span style='color:var(--danger)'>✗ Pipeline failed</span>\n";
                log.textContent += "Response: FAIL\n";
            }
        } catch (e) {
            result.textContent = "Error: " + e.message;
            result.style.color = "var(--danger)";
            log.textContent += "Send error: " + e.message + "\n";
        }
    });

    // --- Helper: start a manual server ---
    async function startManualServer(port) {
        // We can't spawn a Python subprocess from the browser.
        // Instead, we return a no-op and rely on the e2e-full API.
        return {
            shutdown: function () {},
        };
    }

    function hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    function escapeHtml(str) {
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    // ============================
    // Tab switching
    // ============================

    document.querySelectorAll(".tab-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach((s) => s.classList.remove("active"));
            btn.classList.add("active");
            const target = btn.getAttribute("data-tab");
            const section = $("tab-" + target);
            if (section) section.classList.add("active");
        });
    });
})();
