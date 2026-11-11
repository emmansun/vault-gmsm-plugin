# Transit 引擎参考

[English](transit.md) | 简体中文

`gmsm` 挂载点是一个 transit 密钥引擎，提供 SM4-GCM 加解密与 SM2 签名。密钥既可以在 Vault 内部
生成，也可以导入现有密钥材料；除非标记为可导出，否则它不会离开挂载点。

请求与响应的数据结构沿袭 Vault 1.14 的 transit 密钥引擎，因此现有的 transit 工具、策略和客户端库
只需调整挂载路径即可继续使用。与它不同的地方列在[与 Vault transit 的差异](#与-vault-transit-的差异)
一节。

安装与快速开始见 [README](../README.zh-CN.md)。

## 目录

- [Transit 引擎参考](#transit-引擎参考)
  - [目录](#目录)
  - [密钥类型](#密钥类型)
    - [`sm4-gcm96`](#sm4-gcm96)
    - [`sm2`](#sm2)
  - [接口参考](#接口参考)
    - [创建密钥](#创建密钥)
    - [密钥配置](#密钥配置)
    - [加密与解密](#加密与解密)
    - [数据密钥](#数据密钥)
    - [签名与验签](#签名与验签)
    - [哈希与 HMAC](#哈希与-hmac)
    - [导出](#导出)
  - [证书](#证书)
  - [导入密钥](#导入密钥)
  - [与 Vault transit 的差异](#与-vault-transit-的差异)
  - [未实现的特性](#未实现的特性)

## 密钥类型

### `sm4-gcm96`

SM4 的 GCM 模式，密钥长度 128 位，nonce 长度 96 位。除非调用方自己提供，否则每次请求都会生成
新的 nonce。

| 特性 | 说明 |
| --- | --- |
| 密钥派生 | 创建时指定 `derived=true`；此后每个请求都带一个 `context`，用于派生本次请求所用的密钥 |
| 收敛加密 | 需要 `derived=true`；请求必须同时提供 `context` 和 96 位 `nonce`，两者相同则密文相同 |
| 附加数据 | `associated_data` 只参与认证、不参与加密，也不会随密文保存，所以解密时必须再次提供 |
| 密钥长度 | 固定 128 位 |

创建时只给 `convergent_encryption=true` 而不给 `derived=true` 会被拒绝；收敛加密的密钥在加密时
漏掉 context 或 nonce，同样会被拒绝。

### `sm2`

`sm2` 是 256 位素数域曲线 `sm2p256v1` 上的 SM2 密钥：同一把密钥既能用于加密（SM2 公钥
加密）和签名，也能保存一条与之配套的证书链。

签名覆盖 SM3 摘要和 SM2 用户标识，后者是签名所保护的 `Z` 值的一部分：

| 字段 | 行为 |
| --- | --- |
| `uid` | 混入 `Z` 值的用户标识，默认是标准值 `1234567812345678`，不设置时与普通 SM2 实现一致 |
| `prehashed` | 输入已经是 SM3 摘要时设为 `true`。此时不再重新计算 `Z` 值，`uid` 也就不起作用 |
| `marshaling_algorithm` | `asn1`（默认）输出 OpenSSL 与 X.509 使用的 DER `SEQUENCE { r, s }`；`jws` 输出 URL 安全 base64 编码的 64 字节 `r‖s` |

签名只有用创建它时的标识才能验证通过。签名带有密钥版本（`vault:v1:…`），所以验签会自动选用正确的
版本，轮换也不会让更早的签名失效。

## 接口参考

所有路径都相对于挂载点，示例中挂载点为 `gmsm`。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| POST | `keys/:name` | 创建密钥，或更新已有密钥的配置 |
| LIST | `keys` | 列出密钥名 |
| GET | `keys/:name` | 读取密钥元数据以及每个版本的公钥 |
| DELETE | `keys/:name` | 删除密钥；需要 `deletion_allowed` |
| POST | `keys/:name/config` | 修改密钥配置 |
| POST | `keys/:name/rotate` | 新增一个密钥版本 |
| POST | `keys/:name/import` | 用导入的材料创建密钥 |
| POST | `keys/:name/import_version` | 为导入的密钥追加版本 |
| POST | `keys/:name/trim` | 删除低于 `min_available_version` 的版本 |
| POST | `keys/:name/csr` | 为某个版本生成证书请求 |
| POST | `keys/:name/set-certificate` | 保存外部签发的证书链 |
| POST | `encrypt/:name` | 加密 |
| POST | `decrypt/:name` | 解密 |
| POST | `rewrap/:name` | 用最新版本重新加密已有密文 |
| POST | `datakey/plaintext/:name`、`datakey/wrapped/:name` | 生成数据密钥 |
| POST | `sign/:name` | 签名 |
| POST | `verify/:name`、`verify/:name/:urlalgorithm` | 验签；传入 `hmac` 时校验 HMAC |
| POST | `hmac/:name`、`hmac/:name/:urlalgorithm` | 计算 HMAC-SM3 |
| POST | `hash`、`hash/:urlalgorithm` | 用 SM3 计算哈希 |
| GET | `export/:type/:name`、`export/:type/:name/:version` | 导出密钥材料 |
| GET | `backup/:name` | 备份密钥 |
| POST | `restore`、`restore/:name` | 恢复密钥 |
| POST、GET | `config/keys` | 挂载点级别的密钥设置 |
| POST、GET | `cache-config` | 内存中策略缓存的大小 |

### 创建密钥

```bash
vault write gmsm/keys/app-key type=sm2
vault write gmsm/keys/session-key derived=true convergent_encryption=true exportable=true
vault write gmsm/keys/mac-key type=hmac key_size=64
```

| 字段 | 适用类型 | 说明 |
| --- | --- | --- |
| `type` | 全部 | `sm4-gcm96`（默认）、`sm2`、`hmac` |
| `derived` | `sm4-gcm96` | 启用按请求的密钥派生 |
| `convergent_encryption` | `sm4-gcm96` | 需要 `derived` |
| `exportable` | 全部 | 允许导出私有材料 |
| `allow_plaintext_backup` | 全部 | 把密钥标记为可以做明文备份 |
| `auto_rotate_period` | 全部 | 时长，`0` 表示关闭；最小 `1h` |
| `key_size` | `hmac` | 字节数，32 至 512 |

读取密钥会返回它的配置、持有的版本，以及每个版本的公钥：

```console
$ vault read gmsm/keys/app-key
Key                       Value
---                       -----
allow_plaintext_backup    false
auto_rotate_period        0s
deletion_allowed          false
derived                   false
exportable                false
keys                      map[1:map[certificate_chain: creation_time:2026-11-10T11:54:17+08:00 name:sm2p256v1 public_key:-----BEGIN PUBLIC KEY----- …]]
latest_version            1
min_decryption_version    1
min_encryption_version    0
name                      app-key
supports_decryption       true
supports_derivation       false
supports_encryption       true
supports_signing          true
type                      sm2
```

### 密钥配置

`keys/:name/config` 修改创建之后仍然可以调整的设置：`min_decryption_version`、
`min_encryption_version`、`deletion_allowed`、`exportable`、`allow_plaintext_backup` 和
`auto_rotate_period`。低于 `min_decryption_version` 的版本无法解密、包装或导出，这正是退役一个
已泄露版本的办法。

### 加密与解密

```bash
vault write gmsm/encrypt/mykey plaintext="$(printf 'secret' | base64)"
vault write gmsm/decrypt/mykey ciphertext=vault:v1:…
vault write gmsm/rewrap/mykey ciphertext=vault:v1:…
```

`encrypt` 和 `rewrap` 接受 `key_version` 来锁定使用的版本；`decrypt` 从密文本身读取版本。三者都
接受 `batch_input`，它是一组条目，结果按请求顺序放在 `data.batch_results` 中返回。`encrypt` 和
`decrypt` 会在原地标记失败的条目，`partial_failure_response_code` 则决定只有部分条目失败时返回
什么状态码。

`encrypt` 会在密钥不存在时自动创建一个，交互使用时很方便，在生产环境中却容易出乎意料。
`config/keys` 可以关掉这个行为：

```bash
vault write gmsm/config/keys disable_upsert=true
```

### 数据密钥

```console
$ vault write -f gmsm/datakey/plaintext/mykey
Key            Value
---            -----
ciphertext     vault:v1:…
key_version    1
plaintext      …

$ vault write -f gmsm/datakey/wrapped/mykey
```

两个路径都生成一个随机密钥，并用指定的密钥把它包装后返回；`datakey/plaintext/:name` 还会额外返回
base64 编码的密钥本身，`datakey/wrapped/:name` 则从不暴露它。`bits` 选择数据密钥的长度，可取 128、
256 或 512，默认 128。

### 签名与验签

```console
$ vault write gmsm/sign/app-key input="$(printf 'hello' | base64)"
Key          Value
---          -----
signature    vault:v1:MEUCIQDf…

$ vault write gmsm/verify/app-key input="$(printf 'hello' | base64)" \
    signature=vault:v1:MEUCIQDf…
Key      Value
---      -----
valid    true
```

用某个标识签名，再用同一个标识验签：

```console
$ INPUT="$(printf 'hello' | base64)"
$ SIG="$(vault write -field=signature gmsm/sign/app-key input="$INPUT" uid=alice@example.com)"
$ vault write gmsm/verify/app-key input="$INPUT" signature="$SIG" uid=alice@example.com
Key      Value
---      -----
valid    true
```

签名只是对不上时，验签返回 `valid=false` 而不是报错，所以调用方必须检查这个字段。`verify` 也可以
用 `hmac` 代替 `signature`；`hash_algorithm`（或已废弃的 `algorithm`）只选择那次比较所用的摘要，
对签名校验没有影响，后者始终使用 SM3。

### 哈希与 HMAC

```console
$ vault write gmsm/hash input="$(printf 'abc' | base64)" format=hex
Key      Value
---      -----
sum      66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

$ vault write gmsm/hmac/mac-key input="$(printf 'abc' | base64)"
Key      Value
---      -----
hmac     vault:v1:…
```

本插件对外只提供 SM3 一种哈希算法：`hash`、`hmac` 以及 `verify` 的 HMAC 模式都只用它。HMAC 与
签名一样带版本，所以轮换之后 `vault:v1:…` 仍然可以验证通过。

### 导出

```bash
vault read gmsm/export/signing-key/app-key           # 所有版本
vault read gmsm/export/public-key/app-key/latest    # 单个版本
```

| `type` | 返回 | 前置条件 |
| --- | --- | --- |
| `encryption-key` | SM4 密钥（base64）或 SM2 私钥（PEM） | `exportable` |
| `signing-key` | SM2 私钥（PEM） | `exportable` |
| `hmac-key` | HMAC 密钥（base64） | `exportable` |
| `public-key` | SM2 公钥（PEM） | 无 |
| `certificate-chain` | PEM 证书包，叶子证书在前 | 无 |

## 证书

插件不签发证书，只为自己的密钥生成证书请求，再把外部证书颁发机构（CA）签发的证书链存回来：

```console
$ vault write -field=csr gmsm/keys/app-key/csr version=1 > request.pem
# request.pem 交给你的 CA，取回它签发的证书链
$ vault write gmsm/keys/app-key/set-certificate version=1 \
    certificate_chain="$(cat chain.pem)"
$ vault read gmsm/export/certificate-chain/app-key
```

- `keys/:name/csr` 用已保存的密钥签一个 PKCS#10 请求。传入 `csr` 可以指定模板：它的主题、名称、
  扩展和其他请求属性都会带入，而公钥和签名始终来自选定的密钥版本。不给模板时请求的主题为空，
  这正是只持有一个密钥的调用方所需要的。
- `keys/:name/set-certificate` 接受一个或多个拼接在一起的 PEM 块，叶子证书在前。叶子证书的公钥
  必须属于选定的密钥版本；给别的密钥准备的证书链会被拒绝，所以导出的内容永远不可能证明一个挂载点
  并不持有的密钥。不是证书的 PEM 块会被忽略。
- 证书链按密钥版本保存，由 `export/certificate-chain/:name` 原样返回。

签发证书要求密钥类型支持签名，目前只有 `sm2` 满足。如果希望由同一个挂载点直接签发证书，请使用
[证书颁发机构插件](pki.zh-CN.md)。

## 导入密钥

`keys/:name/import` 用别处生成的材料创建密钥，`keys/:name/import_version` 为本身就是导入而来的
密钥追加材料。两者都在请求体中携带材料，所以传输链路必须可信；Vault transit 的包装密钥交换与
`byok-export` 尚未实现。

```bash
vault write gmsm/keys/imported/import type=sm2 private_key=@private.pem
vault write gmsm/keys/imported/import_version private_key=@next.pem
```

| 字段 | 路径 | 说明 |
| --- | --- | --- |
| `type` | `import` | `sm2`、`sm4-gcm96` 或 `hmac`，必填 |
| `private_key` | 两者 | 仅 `sm2`。PEM，可以是 PKCS#8（`BEGIN PRIVATE KEY`）或 SEC 1（`BEGIN EC PRIVATE KEY`） |
| `public_key` | 两者 | 仅 `sm2`。PEM SPKI（`BEGIN PUBLIC KEY`） |
| `key` | 两者 | 仅 `sm4-gcm96` 和 `hmac`。base64，SM4 为 16 字节，HMAC 为 32 至 512 字节 |
| `exportable` | `import` | 允许再次导出材料 |
| `allow_plaintext_backup` | `import` | 允许明文备份 |
| `allow_rotation` | `import` | 允许 `rotate` 用生成的版本替换导入的版本，默认关闭 |
| `auto_rotate_period` | `import` | 需要 `allow_rotation`，且至少为 `1h` |
| `version` | `import_version` | 补全只持有公钥的那个版本 |

这些路径强制的规则：

- `import` 只负责创建。名称已被占用时返回 `already exists` 并指向 `import_version`，这样一次手误
  就不会把外部材料拼到已有的密钥上。
- `import_version` 只对导入的密钥有效。Vault 自己创建的密钥拒绝追加材料；已经在 Vault 内轮换过的
  导入密钥同样被拒绝，因为它的版本序列里已经有了生成的版本，两者混用会被拒绝而不是悄悄进行。
- 只持有公钥的版本可以用于 `verify` 和 `encrypt`。在 `import_version` 补上私钥之前，`sign` 和
  `decrypt` 会以 "does not contain a private part" 失败；私钥对应的公钥必须与该版本记录的公钥一致，
  补全因此是安全的。
- `export/signing-key` 和 `export/encryption-key` 导出的内容可以直接交给 `import`，密钥就是这样在
  挂载点之间迁移的。
- 导入的密钥报告 `imported_key=true`；允许过轮换的还会报告 `imported_key_allow_rotation`。
- 对未允许轮换的导入密钥，`keys/:name/config` 拒绝设置 `auto_rotate_period`，因为那次轮换永远不会
  发生。

轮换之后，导入的材料作为较旧的版本留在挂载点上，用它们解密和验签一直有效，直到
`min_decryption_version` 把它们退役。

## 与 Vault transit 的差异

| | Vault transit | 本插件 |
| --- | --- | --- |
| 对称算法 | AES-128/256-GCM、ChaCha20-Poly1305 | 仅 SM4-GCM |
| 非对称算法 | ECDSA（P-256、P-384、P-521）、RSA、Ed25519 | 仅 SM2 |
| 哈希 | SHA-2 系列 | 仅 SM3 |
| 签名输入的哈希 | 可配置 | 始终 SM3，也可以作用在预先算好的摘要上 |
| 用户标识 | 无 | `uid`，用于签名和验签，混入 SM2 的 `Z` 值 |
| 密钥导入 | 支持 | `import` 与 `import_version`，只接受明文材料：没有包装密钥，且密钥在 Vault 内轮换过之后 `import_version` 不再可用 |
| 安全的密钥传输 | `wrapping_key`、`byok-export`，以及导入包装后的 `ciphertext` | 未实现；`export`、`import` 和 `backup` 都以明文搬运材料 |

其余行为——带版本的密文与签名、密钥派生、收敛加密、附加数据、批量请求、导出、备份与恢复——都
与 transit 一致。

“安全的密钥传输”一行是有意省略的。transit 的 `wrapping_key` 与 `byok-export` 让密钥可以在两个
Vault 实例之间迁移而不必由任何一方的运维人员接触明文，但 `byok-export` 只有配合能接收它所产出
包装 `ciphertext` 的 `import` 才有意义，而那一半需要一对由挂载点自己保管的包装密钥。这里两者都
没有实现，所以密钥的进出依赖 TLS、`exportable` 与 `allow_plaintext_backup`，以及运维人员只在
该接触材料的地方接触它。

## 未实现的特性

以下特性被有意拒绝，而不是做半成品：

- `sm4-cmac` 密钥，创建时以 `sm4-cmac keys are not supported by this plugin` 失败。
- 用不支持加密、解密或签名的密钥类型执行相应操作。
