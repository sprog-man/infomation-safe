# Agent Working Rules

## Project Overview

This is an **Information Safety Experiment** project demonstrating end-to-end network data security:
- Sensor data simulation & collection
- AES-128 encryption/decryption (from scratch)
- RSA key generation & key encryption (from scratch)
- HMAC-SHA256 message authentication (from scratch)
- TCP server/client for secure network transmission
- Full integration pipeline

---

## Directory Structure

```
infomation-safety2/
├── AGENTS.md                  # This file — project rules & architecture
├── feature_list.json          # Feature backlog with status tracking
├── progress.md                # Session progress log with evidence
├── session-handoff.md         # Inter-session handoff notes
├── init_check.py              # Project initialization verification script
├── main.py                    # Entry point — runs full end-to-end pipeline
│
├── # Data layer
│   ├── sensor_data.py         # Sensor data simulation (temperature, humidity, pressure)
│   └── test_sensor.py         # Tests for sensor data module
│
├── # Cryptography layer (all from scratch, stdlib only)
│   ├── aes_crypto.py          # AES-128 encryption/decryption (ECB + PKCS7)
│   ├── test_aes.py            # Tests for AES module
│   ├── rsa_crypto.py          # RSA key generation, encrypt, decrypt
│   └── test_rsa.py            # Tests for RSA module
│
├── # Authentication layer
│   ├── hmac_auth.py           # HMAC-SHA256 message authentication
│   └── test_hmac.py           # Tests for HMAC module
│
├── # Network layer
│   ├── client.py              # TCP client — generates, encrypts, authenticates, sends
│   └── server.py              # TCP server — receives, verifies, decrypts, outputs
│
└── # Integration
    └── test_end_to_end.py     # End-to-end test: client sends, server receives & verifies
```

**Design principles:**
- Flat structure — all modules at root level (no subpackages).
- Each module has a matching `test_*.py` file.
- No external dependencies — only Python standard library.

---

## Development Architecture

### Layer Model

```
┌─────────────────────────────────────┐
│         main.py (integration)       │
├─────────────────────────────────────┤
│  Network Layer                       │
│  client.py  ◄── TCP ──►  server.py  │
├─────────────────────────────────────┤
│  Application Logic                   │
│  sensor_data.py                     │
├─────────────────────────────────────┤
│  Cryptography Layer                  │
│  aes_crypto.py  (AES-128)           │
│  rsa_crypto.py  (RSA)               │
│  hmac_auth.py   (HMAC-SHA256)       │
└─────────────────────────────────────┘
```

### Dependency Graph

```
sensor_data.py          (no dependencies)
aes_crypto.py           (no dependencies)
rsa_crypto.py           (no dependencies)
hmac_auth.py            (no dependencies)
client.py               → sensor_data, aes_crypto, rsa_crypto, hmac_auth
server.py               → aes_crypto, rsa_crypto, hmac_auth
main.py                 → all modules
```

### Feature Flow

1. **Sensor data** is generated as JSON (temperature, humidity, pressure).
2. **AES-128** encrypts the JSON payload with a randomly generated session key.
3. **RSA** encrypts the AES session key for secure key exchange.
4. **HMAC-SHA256** produces an authentication tag over the ciphertext.
5. **TCP client** sends `[encrypted_payload + hmac_tag]` to the server.
6. **TCP server** verifies HMAC, decrypts AES, outputs original sensor data.

---

## Git 版本管理策略

### 初始化

```bash
git init
echo "__pycache__/".gitignore
echo "*.pyc" >> .gitignore
echo ".env" >> .gitignore
echo "data/" >> .gitignore
```

### 分支策略

```
main          # 稳定版本
├── develop   # 开发主分支
    ├── phase/1-sensor-data
    ├── phase/2-aes-encryption
    ├── phase/3-rsa-keygen
    ├── phase/4-hmac-auth
    ├── phase/5-client-server
    └── phase/6-integration
```

**远程仓库地址**：[sprog-man/infomation-safe](https://github.com/sprog-man/infomation-safe.git)

**提交规范：** 使用 `feat:`, `fix:`, `refactor:`, `docs:`, `test:` 前缀。

示例：
```
feat: implement sensor data simulation module
test(aes): add round-trip and padding tests
fix(hmac): correct HMAC tag computation for empty messages
docs: update AGENTS.md with directory structure
```

### 工作流

1. `git checkout -b phase/N-description` 从 `main` 创建开发分支
2. 本地实现 + 测试，频繁提交
3. 合并到 `main`：`git checkout main && git merge --no-ff phase/N-description`
4. 推送到远程：`git push origin main`

---

## Feature 开发流程（每完成一个 feat 必须依次执行）

每完成一个 feat，**必须严格按以下顺序执行**，不可跳过或颠倒：

1. **实现代码** — 编写模块代码及配套测试
2. **`python init_check.py`** — 验证所有组件能正常加载
3. **`python test_*.py`** — 运行对应测试脚本，确保全部通过
4. **更新 `progress.md`** — 填写证据引用，标注每个 done criteria 对应的文件
5. **`git commit`** — 使用 `feat:` 前缀提交，记录该 feat 的变更详情
6. **更新 `session-handoff.md`** — 写入会话交接记录，方便下次恢复

然后才开始下一个 feat。

核心原则：**One feature at a time. Each feature must pass verification before the next begins.**

---

## Coding Standards

### General Rules

- **One feature at a time.** Do not skip ahead. Each feature must pass verification before the next begins.
- **Write evidence, not claims.** Every completed item in `progress.md` must reference actual files that exist.
- **No external crypto libraries.** Encryption and authentication algorithms MUST be implemented from scratch. Only Python standard library imports allowed.
- **Self-contained.** The entire project must be runnable without external services. Simulate sensor data in code.
- **Comments required.** Every algorithm function must have comments explaining its logic.

### Python Style

- Use type hints for all public function signatures.
- Docstrings: Google-style with Parameters, Returns, Raises sections.
- Maximum line length: 100 characters.
- Use `if __name__ == "__main__":` for module-level demos.

---

## Startup Checklist

1. Read `feature_list.json` to find the active feature.
2. Read `progress.md` to understand current state.
3. Run `python init_check.py` to verify the project builds.

---

## Verification

Before claiming any task is done:
1. Run `python init_check.py` to verify all components load.
2. Run the corresponding test script (`python test_*.py`).
3. Update `progress.md` with evidence references.

---

## Done Criteria

- Code is self-contained and runnable (`python main.py`).
- All five experiment sections covered: encryption, decryption, message authentication, network transmission, data collection process.
- Source code includes comments explaining algorithm logic.
- `progress.md` updated with file references for each completed item.

---

## Session Handoff

At session end, write a handoff entry in `session-handoff.md` so the next session can resume.
