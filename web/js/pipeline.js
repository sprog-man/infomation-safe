/**
 * pipeline.js — Pipeline Visualizer (Tab 1)
 *
 * Sequential 5-step pipeline: Sensor Data → AES Encrypt → RSA Key Encrypt → HMAC → TCP Send
 * Each step's output feeds into the next. Shared state via window.pipelineState.
 */

(function () {
    "use strict";

    const API = "/api";

    const state = {
        sensorJson: null,
        aesKeyHex: "4d79536573734b657931323334353637",
        ciphertextHex: null,
        publicKey: null,
        privateKey: null,
        encryptedKeyHex: null,
        hmacTag: null,
        frameBytes: null,
        tcpResponse: null,
    };

    window.pipelineState = state;

    // --- DOM refs ---
    const $ = (id) => document.getElementById(id);

    function setStatus(stepId, status) {
        const el = $(stepId + "-status");
        if (!el) return;
        el.className = "step-status " + status;
        el.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    }

    function showOutput(stepId, text) {
        const el = $(stepId + "-output");
        if (!el) return;
        el.textContent = text;
    }

    function setLoading(btnId, loading) {
        const btn = $(btnId);
        if (!btn) return;
        btn.disabled = loading;
        btn.textContent = loading ? "..." : btn.textContent;
    }

    // --- Step 1: Generate Sensor Data ---
    $("btn-pipeline-sensor").addEventListener("click", async () => {
        const count = parseInt($("pipeline-count").value) || 5;
        setStatus("step-sensor", "running");
        setLoading("btn-pipeline-sensor", true);
        try {
            const res = await apiPost(API + "/sensor-data", { count });
            state.sensorJson = res.json;
            $("pipeline-plaintext").value = res.json;
            showOutput("step-sensor",
                `Count: ${res.count}\nSize: ${res.size_bytes} bytes\nBatch: ${JSON.stringify(JSON.parse(res.json), null, 2).slice(0, 200)}...`
            );
            setStatus("step-sensor", "success");
            unlockNext("step-aes");
        } catch (e) {
            showOutput("step-sensor", "Error: " + e.message);
            setStatus("step-sensor", "fail");
        } finally {
            setLoading("btn-pipeline-sensor", false);
        }
    });

    // --- Step 2: AES Encrypt ---
    $("btn-pipeline-aes").addEventListener("click", async () => {
        setStatus("step-aes", "running");
        setLoading("btn-pipeline-aes", true);
        try {
            const res = await apiPost(API + "/aes-encrypt", {
                plaintext: state.sensorJson,
                key_hex: state.aesKeyHex,
            });
            state.ciphertextHex = res.ciphertext_hex;
            showOutput("step-aes", `Ciphertext (${res.ciphertext_hex.length / 2} bytes):\n${res.ciphertext_hex.slice(0, 120)}...`);
            setStatus("step-aes", "success");
            unlockNext("step-rsa");
        } catch (e) {
            showOutput("step-aes", "Error: " + e.message);
            setStatus("step-aes", "fail");
        } finally {
            setLoading("btn-pipeline-aes", false);
        }
    });

    // --- Step 3: RSA Key Encrypt ---
    $("btn-pipeline-keys").addEventListener("click", async () => {
        try {
            const res = await apiPost(API + "/keys", { bits: 2048 });
            state.publicKey = res.public_key;
            state.privateKey = res.private_key;
            showOutput("step-rsa-keys",
                `Public exponent: ${res.public_key.e}\nPrivate key generated.`
            );
            $("btn-pipeline-encrypt-key").disabled = false;
        } catch (e) {
            showOutput("step-rsa-keys", "Error: " + e.message);
        }
    });

    $("btn-pipeline-encrypt-key").addEventListener("click", async () => {
        setStatus("step-rsa", "running");
        setLoading("btn-pipeline-encrypt-key", true);
        try {
            const res = await apiPost(API + "/encrypt-key", {
                public_key: state.publicKey,
                aes_key_hex: state.aesKeyHex,
            });
            state.encryptedKeyHex = res.encrypted_key_hex;
            showOutput("step-rsa",
                `Encrypted AES key (${res.encrypted_key_hex.length / 2} bytes):\n${res.encrypted_key_hex.slice(0, 80)}...`
            );
            setStatus("step-rsa", "success");
            unlockNext("step-hmac");
        } catch (e) {
            showOutput("step-rsa", "Error: " + e.message);
            setStatus("step-rsa", "fail");
        } finally {
            setLoading("btn-pipeline-encrypt-key", false);
        }
    });

    // --- Step 4: HMAC ---
    $("btn-pipeline-hmac").addEventListener("click", async () => {
        setStatus("step-hmac", "running");
        setLoading("btn-pipeline-hmac", true);
        try {
            const res = await apiPost(API + "/hmac", {
                key_hex: state.aesKeyHex,
                message_hex: state.ciphertextHex,
            });
            state.hmacTag = res.tag_hex;
            showOutput("step-hmac", `HMAC-SHA256 Tag:\n${res.tag_hex}`);
            setStatus("step-hmac", "success");
            unlockNext("step-tcp");
        } catch (e) {
            showOutput("step-hmac", "Error: " + e.message);
            setStatus("step-hmac", "fail");
        } finally {
            setLoading("btn-pipeline-hmac", false);
        }
    });

    // --- Step 5: TCP Send ---
    $("btn-pipeline-send").addEventListener("click", async () => {
        setStatus("step-tcp", "running");
        setLoading("btn-pipeline-send", true);
        try {
            const res = await apiPost(API + "/e2e-full", { reading_count: 3 });
            showOutput("step-tcp", JSON.stringify(res, null, 2));
            if (res.success) {
                setStatus("step-tcp", "success");
                updateWireframe(state.encryptedKeyHex, state.hmacTag, state.ciphertextHex);

                // Show capture panel
                const tcpPhase = res.phases.find(p => p.phase.includes("TCP"));
                if (tcpPhase) {
                    const capPanel = $("pipeline-capture-panel");
                    capPanel.style.display = "block";

                    if (tcpPhase.details?.capture_hex) {
                        $("pipeline-capture-hex").textContent = tcpPhase.details.capture_hex;
                    }
                    if (tcpPhase.decrypted_sensor_data) {
                        $("pipeline-decrypted-data").textContent = JSON.stringify(tcpPhase.decrypted_sensor_data, null, 2);
                    }
                }
            } else {
                setStatus("step-tcp", "fail");
            }
        } catch (e) {
            showOutput("step-tcp", "Error: " + e.message);
            setStatus("step-tcp", "fail");
        } finally {
            setLoading("btn-pipeline-send", false);
        }
    });

    // --- Helpers ---
    function unlockNext(nextStep) {
        const next = $(nextStep);
        if (next) {
            const statusEl = next.querySelector(".step-status");
            if (statusEl) {
                statusEl.className = "step-status";
                statusEl.id = nextStep + "-status";
                setStatus(nextStep, "pending");
            }
            // Enable first actionable button in next step
            const btn = next.querySelector(".btn-primary");
            if (btn) btn.disabled = false;
        }
    }

    function updateWireframe(encKeyHex, hmacTag, cipherHex) {
        if (!encKeyHex || !cipherHex) return;
        $("wireframe").style.display = "block";
        const encLen = Math.min(encKeyHex.length / 2, 256);
        const hmacLen = Math.min((hmacTag?.length || 0) / 2, 64);
        const ctLen = Math.min(cipherHex.length / 2, 500);
        $("bar-enc-key").style.width = Math.max(encLen, 20) + "px";
        $("bar-hmac-len").style.width = Math.max(hmacLen, 4) + "px";
        $("bar-ciphertext").style.width = Math.max(ctLen, 20) + "px";
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
