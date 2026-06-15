# Experiment Report

对照实验要求，本报告结构如下：

## 一、实验内容概述

对网络传输的数据提取出来，进行加密和认证操作，编写网络传输程序。在发送端将加密和认证后的数据发出，在接收端对接收到的数据验证和解密，提取出原始的传感器数据。

### 系统架构

```
[传感器数据] → [AES-128加密] → [RSA密钥加密] → [HMAC-SHA256认证] → [TCP传输]
                                                              ↓
[原始数据] ← [AES解密] ← [HMAC验证] ← [RSA密钥解密] ← [TCP接收]
```

### 技术选型

| 组件 | 算法 | 密钥长度 | 实现方式 |
|------|------|---------|---------|
| 数据加密 | AES-128 | 128位 | 从 scratch 实现 |
| 密钥交换 | RSA-2048 | 2048位 | 从 scratch 实现 |
| 消息认证 | HMAC-SHA256 | 256位 | 从 scratch 实现 |
| 传输协议 | TCP | - | Python socket |

---

## 二、数据采集

### 2.1 采集工具

**实现文件**: [`data/sensor_data.py`](../data/sensor_data.py)

模拟物联网传感器采集流程，生成结构化JSON数据：

```python
from data.sensor_data import generate_single, generate_batch
```

- `generate_single()` — 生成单条传感器读数（温度、湿度、气压）
- `generate_batch(n)` — 生成包含n条读数的批量数据

### 2.2 数据结构

每条传感器数据包含：
- `timestamp`: ISO 8601 格式时间戳
- `sensor_id`: 传感器唯一标识符
- `readings`: 数组，包含 temperature (°C), humidity (%RH), pressure (hPa)

### 2.3 数据持久化

原始数据保存为 JSON 文件：

```bash
python -c "from data.sensor_data import generate_batch; \
           import json; \
           data = json.loads(generate_batch(5)); \
           with open('sensor_output.json', 'w') as f: json.dump(data, f, indent=2)"
```

---

## 三、加密解密算法

### 3.1 基本原理

#### AES-128 加密算法

AES (Advanced Encryption Standard) 是对称分组密码：
- **分组大小**: 128位 (16字节)
- **密钥长度**: 128位 (16字节)
- **加密轮数**: 10轮
- **工作模式**: ECB (教学用途)

**核心操作**:
1. **SubBytes** — 非线性字节替换（使用S-Box查找表）
2. **ShiftRows** — 行循环移位
3. **MixColumns** — 列混合（GF(2^8)多项式乘法）
4. **AddRoundKey** — 异或轮密钥

**密钥扩展**: 16字节原始密钥扩展为11个轮密钥（共176字节）

#### RSA-2048 密钥加密

RSA是非对称公钥密码系统：
1. 生成两个大素数 p, q (各1024位)
2. 计算 n = p × q (模数，2048位)
3. 计算 φ(n) = (p-1)(q-1)
4. 选择公钥指数 e = 65537
5. 计算私钥 d = e^(-1) mod φ(n)

**加密**: c = m^e mod n
**解密**: m = c^d mod n

### 3.2 主要代码及注释

**AES实现**: [`crypto/aes_crypto.py`](../crypto/aes_crypto.py)
- S-Box 查找表: 73行
- key_expansion: 密钥扩展
- sub_bytes / shift_rows / mix_columns / add_round_key: 四轮操作
- aes_encrypt / aes_decrypt: 完整加解密流程

**RSA实现**: [`crypto/rsa_crypto.py`](../crypto/rsa_crypto.py)
- generate_keypair: 素数生成 + 密钥计算
- rsa_encrypt / rsa_decrypt: 公钥加密/私钥解密

### 3.3 执行界面

```bash
# 独立加密演示（无需服务器）
python main.py --demo

# 输出示例:
# [1] Generating RSA-2048 key pair...
# [2] Generating sensor data...
# [3] Encrypting with AES-128...
# [4] Encrypting AES key with RSA-2048...
# [5] Computing HMAC-SHA256...
# [6] Verifying HMAC...
# [7] Decrypting AES key with RSA...
# [8] Decrypting sensor data...
# [9] Verifying roundtrip...
#     [OK] Roundtrip verified!
```

---

## 四、消息认证（签名）

### 4.1 基本原理

**HMAC-SHA256** 是基于哈希的消息认证码：

```
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
```

其中：
- K' = HMAC密钥（此处为AES会话密钥）
- opad = 0x5c重复64次（外填充）
- ipad = 0x36重复64次（内填充）
- H = SHA-256

**SHA-256** 是安全哈希算法：
- 输出256位 (32字节) 哈希值
- 64轮压缩函数
- 基于前8个素数平方根的小数部分初始化哈希值

### 4.2 主要代码及注释

**HMAC实现**: [`auth/hmac_auth.py`](../auth/hmac_auth.py)
- sha256_hash: SHA-256完整实现
- hmac_sha256: HMAC构造
- compute_tag / verify_tag: 标签计算与验证

### 4.3 认证流程

```
客户端:
  1. 用AES密钥加密传感器数据 → 密文
  2. 用AES密钥对密文计算HMAC-SHA256 → 认证标签
  3. 发送 [RSA加密密钥 | HMAC标签 | 密文]

服务端:
  1. 用RSA私钥解密获取AES密钥
  2. 用AES密钥对密文重新计算HMAC
  3. 比较HMAC标签 → 一致则解密，否则拒绝
```

---

## 五、网络传输

### 5.1 实验步骤

#### 发送端 (Client)

**实现文件**: [`network/client.py`](../network/client.py)

1. 加载RSA公钥
2. 生成传感器数据 (JSON)
3. 生成AES会话密钥
4. AES加密传感器数据
5. RSA加密AES会话密钥
6. HMAC-SHA256计算认证标签
7. 组装数据帧并TCP发送

#### 接收端 (Server)

**实现文件**: [`network/server.py`](../network/server.py)

1. TCP监听并接受连接
2. 接收数据帧
3. RSA私钥解密获取AES会话密钥
4. HMAC验证数据完整性
5. AES解密获取原始传感器数据
6. 输出原始JSON数据

### 5.2 数据帧格式

```
┌────────────────┬──────────────┬──────────────┐
│ RSA-enc key    │ HMAC tag     │ Ciphertext   │
│ (256 bytes)    │ (64 bytes)   │ (variable)   │
└────────────────┴──────────────┴──────────────┘
```

### 5.3 端到端演示

```bash
# 本地端到端测试（嵌入式服务器线程）
python main.py --e2e

# 完整验证（测试 + E2E）
make check
```

### 5.4 多机部署

实验要求在两台机器上分别充当发送端与接收端：

**发送端机器**:
```bash
python -c "from network.client import run_client; run_client('192.168.1.100', 9999)"
```

**接收端机器**:
```bash
python -c "from network.server import run_server; run_server('0.0.0.0', 9999)"
```

### 5.5 前端展示

实验要求有前端展示页面。可通过以下方式查看传输结果：

```bash
# 运行完整流水线并查看输出
python main.py

# 输出将显示:
# - 原始传感器数据 (JSON)
# - 加密后密文 (hex)
# - HMAC认证标签
# - 解密后的原始数据 (用于比对)
```

---

## 附录：测试验证

| 模块 | 测试文件 | 测试数 | 验证内容 |
|------|---------|--------|---------|
| 传感器数据 | test_sensor.py | 15 | 数据格式、时间戳、批量生成 |
| AES加密 | test_aes.py | 23 | 加解密往返、NIST向量、填充 |
| RSA加密 | test_rsa.py | 28 | 密钥生成、加解密往返、素数检测 |
| HMAC认证 | test_hmac.py | 20 | SHA-256向量、HMAC标签、篡改检测 |
| 客户端 | test_client.py | 9 | 帧格式、HMAC有效性、篡改拒绝 |
| 服务端 | test_server.py | 4 | 往返、篡改拒绝、无效HMAC |
| **合计** | | **99** | **全部通过** |
