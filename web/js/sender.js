/**
 * sender.js — Sender Web UI (Automated Crypto Pipeline)
 *
 * Select city → click "一键加密传输" → fetch real weather, display it,
 * then run all crypto steps automatically. Sender can only encrypt,
 * never decrypt. Hash display shows client-side hash only (can't compare).
 */

(function () {
    "use strict";

    const API = "/api";
    const $ = (id) => document.getElementById(id);

    // --- Main: one-click crypto pipeline ---
    $("btn-start").addEventListener("click", async () => {
        const city = $("weather-city").value;
        const stepCards = $("step-cards");
        stepCards.innerHTML = '<div class="phase-item"><p>正在运行加密流水线...</p></div>';
        $("step-display").style.display = "none";
        $("weather-display").style.display = "none";

        $("btn-start").disabled = true;
        $("btn-start").textContent = "加密传输中...";

        try {
            const res = await apiPost(API + "/weather/send", { city, api_key: "" });
            if (res.error) throw new Error(res.error);

            // Display raw weather data with Wireshark table
            if (res.raw_json) {
                try {
                    $("json-display").textContent = JSON.stringify(JSON.parse(res.raw_json), null, 2);
                } catch {
                    $("json-display").textContent = res.raw_json;
                }
            }

            if (res.client_hash) {
                $("hash-display").textContent =
                    "MD5:    " + res.client_hash.md5 + "\n" +
                    "SHA256: " + res.client_hash.sha256 + "\n" +
                    "注：本哈希为发送端原始数据的完整性摘要，接收端可在其页面查看解密后哈希并进行对比。";
            }

            // Build Wireshark-style hex table from HTTP response
            if (res.http_response_hex) {
                buildPacketTable(res.http_response_hex, "sender-packet-body");
            }

            $("weather-display").style.display = "block";

            // Render all crypto steps (hash comparison step removed)
            stepCards.innerHTML = "";
            res.steps.forEach((s) => {
                if (s.step === "Hash Comparison") return; // skip, sender can't compare
                const card = buildStepCard(s);
                stepCards.appendChild(card);
            });

            $("step-display").style.display = "block";

        } catch (e) {
            stepCards.innerHTML = '<div class="step-card step-error"><div class="step-header"><h3>✗ 错误</h3></div><div class="step-body"><pre>' + escapeHtml(e.message) + '</pre></div></div>';
        } finally {
            $("btn-start").disabled = false;
            $("btn-start").textContent = "▶ 一键加密传输";
        }
    });

    // --- Build a visual step card ---
    function buildStepCard(step) {
        const card = document.createElement("div");
        card.className = "step-card step-" + step.status;

        const header = document.createElement("div");
        header.className = "step-header";
        const icon = step.icon || (step.status === "success" ? "✓" : "✗");
        header.innerHTML = `
            <span class="step-icon">${icon}</span>
            <h3>${step.step}</h3>
            <span class="step-badge step-badge-${step.status}">${step.status}</span>
            <span class="step-time">${step.time_s ? step.time_s + "s" : ""}</span>
        `;
        card.appendChild(header);

        const body = document.createElement("div");
        body.className = "step-body";

        if (step.error) {
            body.innerHTML += `<div class="step-error-msg">Error: ${escapeHtml(step.error)}</div>`;
        }

        if (step.details) {
            for (const [key, val] of Object.entries(step.details)) {
                const row = document.createElement("div");
                row.className = "step-detail-row";
                const label = document.createElement("span");
                label.className = "step-detail-key";
                label.textContent = formatLabel(key) + ":";
                row.appendChild(label);
                const value = document.createElement("span");
                value.className = "step-detail-value";
                value.textContent = typeof val === "object" ? JSON.stringify(val, null, 2) : String(val);
                row.appendChild(value);
                body.appendChild(row);
            }
        }

        if (step.data) {
            for (const [key, val] of Object.entries(step.data)) {
                const row = document.createElement("div");
                row.className = "step-data-row";
                const label = document.createElement("div");
                label.className = "step-data-label";
                label.textContent = formatLabel(key) + ":";
                row.appendChild(label);
                const pre = document.createElement("pre");
                pre.className = "step-data-pre";
                pre.textContent = typeof val === "object" ? JSON.stringify(val, null, 2) : String(val);
                row.appendChild(pre);
                body.appendChild(row);
            }
        }

        card.appendChild(body);
        return card;
    }

    function formatLabel(key) {
        return key
            .replace(/_/g, " ")
            .replace(/\b\w/g, (c) => c.toUpperCase());
    }

    // --- Build Wireshark-style packet table ---
    function buildPacketTable(hexStr, tbodyId) {
        const tbody = $(tbodyId);
        if (!tbody) return;
        tbody.innerHTML = "";

        const maxBytes = 2048;
        const bytes = hexStr.slice(0, maxBytes * 2);
        const len = bytes.length / 2;
        const bytesPerRow = 16;

        for (let row = 0; row < len; row += bytesPerRow) {
            const tr = document.createElement("tr");

            const tdOffset = document.createElement("td");
            tdOffset.textContent = row.toString(16).padStart(8, "0").toUpperCase();
            tr.appendChild(tdOffset);

            const tdHex = document.createElement("td");
            let hexParts = [];
            for (let col = 0; col < bytesPerRow; col++) {
                const idx = (row + col) * 2;
                if (idx + 1 < bytes.length) {
                    hexParts.push(bytes.substr(idx, 2));
                }
            }
            tdHex.textContent = hexParts.join(" ");
            tr.appendChild(tdHex);

            const tdAscii = document.createElement("td");
            let ascii = "";
            for (let col = 0; col < bytesPerRow; col++) {
                const idx = (row + col) * 2;
                if (idx + 1 < bytes.length) {
                    const byteVal = parseInt(bytes.substr(idx, 2), 16);
                    ascii += byteVal >= 32 && byteVal <= 126 ? String.fromCharCode(byteVal) : ".";
                }
            }
            tdAscii.textContent = ascii;
            tr.appendChild(tdAscii);

            tbody.appendChild(tr);
        }
    }

    function escapeHtml(str) {
        if (typeof str !== "string") str = String(str);
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    async function apiPost(url, body) {
        const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        return data;
    }
})();
