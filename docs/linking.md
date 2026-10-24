> **Status (2026-10-23): not possible for WebAuthn; shelved for good.** An
> Android phone (Pixel 7 Pro, Google Password Manager) was tested against a
> working implementation of §1.1 (QR key 4 = true, keys 0-5 like Chrome,
> linking accepted from the post-handshake message or from update messages up
> to 3 minutes after the reply). Over three QR transactions it sent no linking
> information and no update message at all. The reason is upstream: Chromium
> disabled hybrid linking for WebAuthn behind a flag in October 2024
> (crbug.com/372493822, commit 1e63cf3d14) and removed the linking UI in June
> 2025 (f69542acd1). `ShouldOfferLinking()` now returns false for every
> WebAuthn request ("Hybrid linking is not supported for WebAuthn"). Phones now
> reach Chrome without a QR code only through Google account sync, which other
> clients cannot use. The implementation is in this repository's history
> (2ea0428, reverted in the following commit).

# State-assisted Linking（FR-7）设计

> **状态（2026-09-29）：搁置。** L0 真机验证结果：iOS（iPhone，iCloud
> Keychain）在 QR 声明 `supports_linking=true` 后，makeCredential 与
> getAssertion 两种仪式均无"记住这台电脑"选项，事务后也不发 linking
> update 消息——iOS 当前不支持 linking。Android（Google Password Manager）
> 按 Chromium 实现推断支持，但无设备未验证。待有 Android 真机后按本文档
> 从 L1 继续。代码侧已删除从未可达的 linking 分支（等待 update 消息的
> 会话路径及相应 HKDF 用途），恢复时需按本文档重新实现。

> 目标：手机与桌面第一次通过 QR 建立联系后互相"记住"对方，后续操作免扫码——
> 桌面通过隧道服务器经 FCM/APNs 推送唤醒手机，BLE 广播仍作 proximity proof。
> 规范来源：PXP §5.3.2 + Chromium `device/fido/cable`（pairing.cc、
> fido_tunnel_device.cc 的 paired 路径、v2_handshake.cc 的 NKpsk0）。

## 1. 协议流程

### 1.1 第一阶段：QR 事务中获取 linking 数据

- QR payload key 4 `supports_linking` 置 `true`（当前实现为 `false`，手机因此
  不提供 linking）。
- 事务完成后，手机经隧道发 **update 消息**（type=2），内容为 canonical CBOR map：

| key | 内容 |
| --- | --- |
| 1 | linking map（map 嵌套） |
| 0 | （可选）填充用全零 bytestring |

linking map 内部：

| key | 内容 | 大小 |
| --- | --- | --- |
| 1 | contact ID（不透明，隧道服务器凭它联系手机；Android 为 FCM token） | 变长 |
| 2 | link ID（本桌面在手机侧的标识，回连时需回传） | 8B |
| 3 | link secret（后续握手的根密钥） | 32B |
| 4 | 手机公钥（P-256 X9.62 未压缩，手机的全局身份） | 65B |
| 5 | 手机名称（如 "Pixel 3 XL"） | 文本 |
| 6 | 签名 | 32B |

- **签名必须验证**：`HMAC-SHA256(key = ECDH(桌面 identity 私钥, 手机公钥),
  数据 = handshake_hash)`。handshake_hash 是 Noise 会话的 channel binding，
  内含桌面生成的随机量，保证新鲜性。验证失败 → 丢弃 linking 数据。
  （桌面 identity 已持久化，见 `src/identity.rs`：与 Chromium 的 per-device
  身份对齐，linking 落地后手机可跨事务识别本桌面。）
- 桌面发出 shutdown 后仍需继续接收 update 消息（spec 建议至少 2 分钟；
  实务窗口 ~15s）。CTAP 应答先行回给 Firefox，linking 接收在后台收尾。

### 1.2 第二阶段：免扫码回连

1. 生成 16B client_nonce。构造 client payload（canonical CBOR）：
   `{1: linkID, 2: client_nonce, 3: "mc"|"ga"}`。
2. WSS 连接 `wss://<domain>/cable/contact/<base64url(contactID, 去 padding)>`，
   请求头：`X-caBLE-Client-Payload: <hex(client payload)>`，
   `X-caBLE-Signal-Connection: true`，子协议 `fido.cable`。
   - 410 Gone → 手机端已解除链接或永久不可达 → 删除本地记录，回落 QR。
3. 隧道服务器经厂商推送通道唤醒手机；手机创建隧道并开始 BLE 广播。
4. EID key = `Derive(linkSecret, salt=client_nonce, EIDKey)`（64B）。
   paired 流程的 EID plaintext = `[0x00] + 15B 随机 nonce`（**不含 routing ID**——
   桌面已在 contact 连接上等好，advert 只承担 proximity proof）。
5. 扫描到 advert 并解密后：PSK = `Derive(linkSecret, salt=plaintextEID, PSK)`。
6. 握手 = **Noise NKpsk0**：桌面为 initiator，`peer_identity` = 存储的手机公钥
   （已有 `HandshakeInitiator::new_paired` 骨架）。之后 post-handshake、CTAP
   透传与 QR 流程完全一致。

## 2. 模块设计

### 2.1 新增 `src/links.rs` — 联系人存储

```text
Link {
  contact_id: Vec<u8>,        // 隧道服务器 opaque
  link_id: [u8; 8],
  link_secret: [u8; 32],      // 敏感
  peer_public_key: [u8; 65],  // 手机身份公钥
  name: String,
  tunnel_domain: u16,
  created: u64,
}
```

- 路径 `$XDG_DATA_HOME/ucabled/links.json`（默认 `~/.local/share/ucabled/`），
  文件权限 0600（NFR-6）；写入用临时文件 + rename 保证原子性。
- 多台手机多条记录；410 或验证失败时删除对应条目。
- 序列化：serde_json（引入 `serde` + `serde_json`，字段 hex 编码）。

### 2.2 `src/session.rs` — 两条路径

- `run_qr`（现有）：QR 事务。改动：`supports_linking=true`；CTAP 应答后
  保持隧道监听 update 消息（~15s），解析 + 验签 linking 数据，返回
  `Option<Link>`。
- `run_paired(link, ctap_command)`：contact URL + client payload 头 →
  等 BLE advert（EID key 由 linkSecret+client_nonce 派生）→ NKpsk0 →
  复用现有 CTAP 透传。

### 2.3 `src/tunnel.rs`

- `contact_url(domain, contact_id)`；`dial` 支持自定义请求头
  （`X-caBLE-Client-Payload`、`X-caBLE-Signal-Connection`）；410 单独映射为
  `LinkGone` 错误。

### 2.4 daemon 编排（`src/bin/ucabled.rs`）

```
 ┌────────────────────────┐
 │        事务开始        │
 └────────────┬───────────┘
              │
 ┌────────────────────────┐
 │      links 非空？      │
 └────────────┬───────────┘
              ├──────── 否 ────────> ┌────────────┐
              │ 是                   │  QR 流程   │
              V                      └────────────┘
 ┌────────────────────────┐
 │   并发尝试所有联系人   │
 └────────────┬───────────┘
              │
 ┌────────────────────────┐
 │         成功？         │
 └────────────┬───────────┘
              ├──────── 否 ────────> ┌────────────────┐
              │ 是                   │  回落 QR 流程  │  全失败 / 超时（~20s）
              V                      └────────────────┘
 ┌────────────────────────┐
 │ 显示"连接中"（无 QR）  │
 └────────────────────────┘
```

- 配置：全局 `linking = true|false`（默认 true）；`ucabled links list/remove`
  管理子命令（可选，MVP 可手工删文件）。
- 日志：不落 linkSecret/contactID 原文（NFR-6），只记名称与长度。

### 2.5 UI（`src/bin/ucable-agent-helper.rs`）

- 增加"连接中"模式：`ucable-agent-helper --connecting <手机名>`——无 QR，
  显示手机名 + 旋转指示 + Cancel。模式参数为 argv，Notifier 接口不变。

### 2.6 mock phone 扩展（测试）

- QR 阶段：握手后发送合法 linking update（含正确签名）。
- paired 阶段：接受 contact 连接、广播 paired EID、响应 NKpsk0。
- 本地 E2E：先 QR 事务拿到 Link，再 paired 事务免 QR 全往返。

## 3. 安全考量

- linkSecret 是全权的：泄露 = 可冒充桌面联系手机。0600 权限 + 不落日志；
  不进 swap 保护不做（超出范围，交给系统全磁盘加密）。
- 签名验证明白防"隧道服务器伪造 linking 数据替换手机公钥"。
- 410 语义必须遵守：手机解除链接后隧道服务器返回 410，本地立即删除记录，
  避免无限重试。
- paired 流程的 BLE advert 仍是硬 proximity proof，不可跳过。

## 4. 实施步骤与验收

| 步骤 | 内容 | 验收 |
| --- | --- | --- |
| L0 | QR 发 `supports_linking=true` + update 消息监听/解析/验签（不存储） | **真机决策点**：iPhone / Android 是否发来 linking 数据（iOS 支持与否是最大未知数；若 iOS 不支持，功能仅对 Android 生效或整体降级） |
| L1 | `links.rs` 存储 + 0600 + 原子写 | 单元测试 |
| L2 | paired 连接（contact URL、client payload、NKpsk0） | mock phone 本地 E2E 双阶段 |
| L3 | daemon 编排 + UI 连接中模式 + 配置开关 | 手工：先 paired 失败回落 QR，再成功 |
| L4 | 真机验收 | 第一次扫码（勾选记住电脑）→ 第二次操作免扫码推送完成 |

## 5. 工作量预估

链接接收/验签 ~150 行；存储 ~150 行；paired 连接 ~250 行；编排/UI/测试
~300 行。合计约 700–900 行。
