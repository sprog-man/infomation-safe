/**
 * receiver.js — Receiver Web UI (Automated Decryption Pipeline + Hash Comparison)
 */

(function () {
    "use strict";

    const API = "/api";
    const $ = (id) => document.getElementById(id);

    let _latestData = null;
    let _senderHash = null; // fetched from sender

    // --- Fetch sender's original hash for comparison ---
    async function fetchSenderHash() {
        try {
            const res = await fetch("http://127.0.0.1:8080/api/weather/latest-hash");
            if (res.ok) {
                const data = await res.json();
                _senderHash = data.hash;
            }
        } catch {
            // sender not available, that's ok
        }
    }

    // --- Fetch latest decrypted data ---
    async function fetchLatest() {
        $("btn-refresh").disabled = true;
        $("btn-refresh").textContent = "刷新中...";
        $("decrypt-display").style.display = "none";
        $("data-panels").style.display = "none";
        $("hash-compare").style.display = "none";

        try {
            const res = await apiGet(API + "/weather/latest");

            if (!res.available) {
                $("no-data-panel").style.display = "block";
                $("last-received").textContent = "暂无数据";
                return;
            }

            _latestData = res.data;
            $("no-data-panel").style.display = "none";

            // Update status
            $("last-received").textContent = _latestData.received_at || "未知";

            // Render decryption steps
            const steps = _latestData.decryption_steps || [];
            const stepCards = $("decrypt-step-cards");
            stepCards.innerHTML = "";
            const icons = ["📥", "🔑", "🛡", "🔓", "📋"];
            steps.forEach((s, i) => {
                s.icon = icons[i] || "✓";
                const card = buildStepCard(s);
                stepCards.appendChild(card);
            });
            $("decrypt-display").style.display = "block";

            // Show JSON
            const jsonData = _latestData.json_data;
            if (jsonData) {
                $("json-display").textContent = JSON.stringify(jsonData, null, 2);
            } else {
                $("json-display").textContent = "(no JSON data)";
            }

            // Show hash (receiver's own)
            const hash = _latestData.hash;
            if (hash) {
                $("hash-display").textContent =
                    "MD5:    " + hash.md5 + "\n" +
                    "SHA256: " + hash.sha256;
            } else {
                $("hash-display").textContent = "(no hash)";
            }

            // Build packet table
            const httpHex = _latestData.http_response_hex;
            if (httpHex) {
                buildPacketTable(httpHex, "packet-body");
            }

            // Connection info
            const decSteps = _latestData.decryption_steps || [];
            let connInfo = "Frame Size: " + (_latestData.frame_size || 0) + " bytes\n";
            connInfo += "Accepted: " + (_latestData.accepted ? "Yes ✓" : "No ✗") + "\n";
            if (decSteps.length > 0) {
                const firstStep = decSteps[0];
                if (firstStep.details) {
                    connInfo += "Encrypted Key: " + (firstStep.details.encrypted_key_size || 0) + " bytes\n";
                    connInfo += "HMAC Tag: " + (firstStep.details.hmac_tag_size || 0) + " bytes\n";
                    connInfo += "Ciphertext: " + (firstStep.details.ciphertext_size || 0) + " bytes\n";
                }
            }
            $("conn-info-display").textContent = connInfo;

            $("data-panels").style.display = "block";

            // --- Hash Comparison (receiver compares both hashes) ---
            // Receiver has its own hash from decryption.
            // It fetches the sender's hash via HTTP to compare them.
            try {
                const senderResp = await fetch("http://127.0.0.1:8080/api/weather/latest-hash");
                if (senderResp.ok) {
                    const senderData = await senderResp.json();
                    const clientHash = senderData.hash;
                    const serverHash = hash;

                    if (clientHash && serverHash) {
                        const match = clientHash.md5 === serverHash.md5;

                        $("rcv-client-hash").textContent =
                            "MD5:    " + clientHash.md5 + "\n" +
                            "SHA256: " + clientHash.sha256 + "\n" +
                            "(发送端加密前原始数据)";

                        $("rcv-server-hash").textContent =
                            "MD5:    " + serverHash.md5 + "\n" +
                            "SHA256: " + serverHash.sha256 + "\n" +
                            "(接收端解密后数据)";

                        $("rcv-hash-match").textContent = match
                            ? "✓ 哈希匹配 — 数据传输完整，未被篡改！\n发送端与接收端的数据完全一致。"
                            : "✗ 哈希不匹配 — 数据可能已被篡改！";
                        $("rcv-hash-match").className = "mono-output " +
                            (match ? "hash-match" : "hash-mismatch");

                        $("hash-compare").style.display = "block";
                    }
                }
            } catch {
                // Sender hash not available — show just server hash
                $("rcv-client-hash").textContent = "无法获取发送端哈希\n(发送端可能未运行)";
                $("rcv-server-hash").textContent = hash
                    ? "MD5: " + hash.md5
                    : "(无数据)";
                $("rcv-hash-match").textContent = "等待发送端数据...";
            }

            // Enable PCAP download
            $("btn-download-pcap").disabled = !_latestData.accepted;

        } catch (e) {
            $("last-received").textContent = "请求失败: " + e.message;
        } finally {
            $("btn-refresh").disabled = false;
            $("btn-refresh").textContent = "🔄 刷新最新数据";
        }
    }

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

        card.appendChild(body);
        return card;
    }

    function formatLabel(key) {
        return key
            .replace(/_/g, " ")
            .replace(/\b\w/g, (c) => c.toUpperCase());
    }

    // --- Download PCAP ---
    $("btn-download-pcap").addEventListener("click", async () => {
        $("btn-download-pcap").disabled = true;
        $("btn-download-pcap").textContent = "生成中...";

        try {
            const res = await apiPost(API + "/weather/pcap", {});
            if (res.success) {
                const a = document.createElement("a");
                a.href = res.download_url;
                a.download = res.pcap_filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            } else {
                alert("PCAP generation failed: " + (res.error || "unknown error"));
            }
        } catch (e) {
            alert("PCAP error: " + e.message);
        } finally {
            $("btn-download-pcap").disabled = false;
            $("btn-download-pcap").textContent = "📥 下载 PCAP";
        }
    });

    // --- Refresh button ---
    $("btn-refresh").addEventListener("click", fetchLatest);

    // --- Auto-refresh on page load ---
    fetchLatest();

    // --- Helpers ---

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

    async function apiGet(url) {
        const res = await fetch(url);
        return await res.json();
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

    function escapeHtml(str) {
        if (typeof str !== "string") str = String(str);
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
})();
