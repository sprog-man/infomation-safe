/**
 * crypto.js — Crypto Playground (Tab 2)
 *
 * Six independent operations: AES encrypt/decrypt, RSA keygen/encrypt/decrypt, HMAC compute/verify, roundtrip.
 */

(function () {
    "use strict";

    const API = "/api";

    function $(id) { return document.getElementById(id); }

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

    // --- AES Encrypt ---
    $("btn-pg-aes-enc").addEventListener("click", async () => {
        try {
            const res = await apiPost(API + "/aes-encrypt", {
                plaintext: $("pg-aes-plaintext").value,
                key_hex: $("pg-aes-key").value,
            });
            $("pg-aes-cipher").value = res.ciphertext_hex;
            $("pg-aes-result").textContent = "Encrypted ✓";
            $("pg-aes-result").style.color = "var(--success)";
        } catch (e) {
            $("pg-aes-result").textContent = "Error: " + e.message;
            $("pg-aes-result").style.color = "var(--danger)";
        }
    });

    // --- AES Decrypt ---
    $("btn-pg-aes-dec").addEventListener("click", async () => {
        try {
            const res = await apiPost(API + "/aes-decrypt", {
                ciphertext_hex: $("pg-aes-cipher").value,
                key_hex: $("pg-aes-key").value,
            });
            $("pg-aes-result").textContent = res.plaintext;
            $("pg-aes-result").style.color = "var(--success)";
        } catch (e) {
            $("pg-aes-result").textContent = "Error: " + e.message;
            $("pg-aes-result").style.color = "var(--danger)";
        }
    });

    // --- RSA Key Generation ---
    $("btn-pg-rsa-gen").addEventListener("click", async () => {
        const bits = parseInt($("pg-rsa-bits").value);
        $("btn-pg-rsa-gen").textContent = "Generating...";
        $("btn-pg-rsa-gen").disabled = true;
        try {
            const res = await apiPost(API + "/keys", { bits });
            $("pg-rsa-pub-n").value = res.public_key.n.slice(0, 60) + "...";
            $("pg-rsa-priv-d").value = res.private_key.d.slice(0, 60) + "...";
            // Store full keys for other operations
            window._pgPubKey = res.public_key;
            window._pgPrivKey = res.private_key;
        } catch (e) {
            alert("Key generation failed: " + e.message);
        } finally {
            $("btn-pg-rsa-gen").textContent = "Generate Keypair";
            $("btn-pg-rsa-gen").disabled = false;
        }
    });

    // --- RSA Encrypt AES Key ---
    $("btn-pg-rsa-enc").addEventListener("click", async () => {
        try {
            const pubN = $("pg-rsa-pub-n-input").value || (window._pgPubKey?.n || "");
            const pubE = parseInt($("pg-rsa-pub-e-input").value) || 65537;
            const res = await apiPost(API + "/encrypt-key", {
                public_key: { n: pubN, e: pubE },
                aes_key_hex: $("pg-rsa-aes-key").value,
            });
            $("pg-rsa-enc-result").value = res.encrypted_key_hex;
        } catch (e) {
            $("pg-rsa-enc-result").value = "Error: " + e.message;
        }
    });

    // --- RSA Decrypt ---
    $("btn-pg-rsa-dec").addEventListener("click", async () => {
        try {
            const ctHex = $("pg-rsa-dec-ct").value;
            const privD = $("pg-rsa-priv-d-input").value || (window._pgPrivKey?.d || "");
            const nVal = $("pg-rsa-n-input").value || (window._pgPrivKey?.n || "");
            // Use the e2e-full endpoint's internal decrypt logic by calling aes-decrypt
            // Actually we need to decrypt RSA - let's compute it client-side
            const ctBytes = hexToBytes(ctHex);
            const nBig = BigInt("0x" + nVal);
            const dBig = BigInt("0x" + privD);
            const mBig = modPow(BigInt("0x" + ctHex), dBig, nBig);
            const mHex = mBig.toString(16).padStart(ctHex.length, "0");
            const plaintext = bytesFromHex(mHex);
            $("pg-rsa-dec-result").textContent = new TextDecoder().decode(plaintext);
            $("pg-rsa-dec-result").style.color = "var(--success)";
        } catch (e) {
            $("pg-rsa-dec-result").textContent = "Error: " + e.message;
            $("pg-rsa-dec-result").style.color = "var(--danger)";
        }
    });

    // --- HMAC Compute ---
    $("btn-pg-hmac-comp").addEventListener("click", async () => {
        try {
            const res = await apiPost(API + "/hmac", {
                key_hex: $("pg-hmac-key").value,
                message_hex: $("pg-hmac-msg").value,
            });
            $("pg-hmac-tag").value = res.tag_hex;
        } catch (e) {
            $("pg-hmac-tag").value = "Error: " + e.message;
        }
    });

    // --- HMAC Verify ---
    $("btn-pg-hmac-ver").addEventListener("click", async () => {
        try {
            const res = await apiPost(API + "/verify-hmac", {
                key_hex: $("pg-hmac-key").value,
                message_hex: $("pg-hmac-msg").value,
                tag_hex: $("pg-hmac-tag").value,
            });
            $("pg-hmac-valid").textContent = res.valid ? "YES ✓" : "NO ✗";
            $("pg-hmac-valid").style.color = res.valid ? "var(--success)" : "var(--danger)";
        } catch (e) {
            $("pg-hmac-valid").textContent = "Error: " + e.message;
        }
    });

    // --- Quick Roundtrip ---
    $("btn-pg-roundtrip").addEventListener("click", async () => {
        const text = $("pg-roundtrip-text").value;
        const keyHex = $("pg-roundtrip-key").value;
        try {
            const encRes = await apiPost(API + "/aes-encrypt", { plaintext: text, key_hex: keyHex });
            const decRes = await apiPost(API + "/aes-decrypt", {
                ciphertext_hex: encRes.ciphertext_hex,
                key_hex: keyHex,
            });
            $("pg-roundtrip-original").textContent = text;
            $("pg-roundtrip-decrypted").textContent = decRes.plaintext;
            $("pg-roundtrip-status").textContent = text === decRes.plaintext ? "MATCH ✓" : "MISMATCH ✗";
            $("pg-roundtrip-status").style.color = text === decRes.plaintext ? "var(--success)" : "var(--danger)";
        } catch (e) {
            $("pg-roundtrip-status").textContent = "Error: " + e.message;
        }
    });

    // --- Utility ---
    function hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    function bytesFromHex(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    function modPow(base, exp, mod) {
        let result = BigInt(1);
        base = base % mod;
        while (exp > BigInt(0)) {
            if (exp % BigInt(2) === BigInt(1)) {
                result = (result * base) % mod;
            }
            exp = exp / BigInt(2);
            base = (base * base) % mod;
        }
        return result;
    }
})();
