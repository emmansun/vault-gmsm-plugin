# 证书颁发机构插件 pki-gmsm

[English](pki.md) | 简体中文

`pki-gmsm` 是证书颁发机构（CA），不是 transit 引擎：它生成 SM2 密钥、用 `SM2WithSM3` 签发 X.509
证书、发布 CRL 并响应 OCSP 状态查询。它是独立的挂载类型，因为 Vault 规定一个挂载只能绑定一个
插件，而且 CA 的生命周期与 transit 密钥完全不同。

它单独挂载，与 [transit 引擎](transit.zh-CN.md) 互不相干，使用自己的路径：

```bash
PLUGIN_NAME=pki-gmsm
CHECKSUM=$(sha256sum "$PLUGIN_DIR/$PLUGIN_NAME" | cut -d' ' -f1)

vault plugin register -sha256="$CHECKSUM" secret pki-gmsm
vault secrets enable -path=pki-gmsm pki-gmsm
```

二进制文件名与注册名是同一个字符串，因为 Vault 只按 `$PLUGIN_DIR/<注册名>` 查找，不会尝试带前缀
的变体。挂载路径可以自选，这里是 `pki-gmsm`，以免与内置的 `pki` 引擎冲突——后者通常已经占用了
`pki/`。下文所有路径都相对于挂载点。

一个挂载点持有交给它的若干颁发机构，并用其中之一签名：最初生成或导入的那个，或者用
`issuer/:ref/default` 选定的那个。`issuers` 列出它们，`issuer/:ref` 读取其中之一，可以用标识、
名称或单词 `default` 定位，并回答它是否正在使用。`root/rotate/:type` 在旧机构旁边生成一个新机构，
并从那时起用它签名；旧机构保留下来，所以它签发过的证书仍然可以验证通过，它吊销的证书也仍然记在
它自己的列表里。
`DELETE /issuer/:ref` 退役其中一个，但只能在其证书过期之后。`config/ca` 用于接收在别处创建的
颁发机构。

## 目录

- [生成颁发机构](#生成颁发机构)
- [颁发机构的轮换与退役](#颁发机构的轮换与退役)
  - [外部签名器](#外部签名器)
  - [颁发机构的用途](#颁发机构的用途)
- [角色](#角色)
  - [角色名与存储](#角色名与存储)
  - [仅用于签名的证书](#仅用于签名的证书)
  - [证书声明的内容](#证书声明的内容)
- [签发与签名](#签发与签名)
- [证书读取与吊销](#证书读取与吊销)
  - [增量 CRL](#增量-crl)
- [响应器 OCSP](#响应器-ocsp)
- [中间颁发机构](#中间颁发机构)
- [与 Vault pki 的差异](#与-vault-pki-的差异)

## 生成颁发机构

```console
$ vault write pki-gmsm/root/generate/internal common_name="Example Root CA" ttl=87600h
Key            Value
---            -----
certificate    -----BEGIN CERTIFICATE-----…
issuing_ca     -----BEGIN CERTIFICATE-----…
ca_chain       [-----BEGIN CERTIFICATE-----…]
serial_number  1F:2C:0E:…
expiration     1798761600
issuer_id      c8f1…
key_id         3a02…
```

`internal` 把私钥留在挂载点内，从不返回；`exported` 在响应中返回一次私钥，格式为 SEC 1
（`private_key_format=der`，默认）或 PKCS#8。有效期默认十年，`max_path_length` 默认 `-1`，
即允许其下任意层级的中间 CA。

颁发机构证书带有 SM3 主体密钥标识符（SKI，公钥的 SM3 摘要取前 160 位），并把同一个值用作颁发者
密钥标识符（AKI）。自签名证书的 AKI 与 SKI 相同，证书链查到这里就落在它自己身上，到此终止。
`ca`、`ca/pem`（原始 `application/pem-encoding`）和 `ca_chain` 可以读回它。

`DELETE pki-gmsm/root` 会删除颁发机构、它的密钥、它签发过的每一张证书以及缓存的 CRL。角色会保留
下来，因为角色是策略而不是颁发机构的状态。每个颁发机构维护自己的 CRL，所以即使挂载点已经换用别的
机构，吊销仍然会进入签发该证书的那个机构的列表。轮换过的挂载点持有多个颁发机构，在那里这个删除会
被拒绝：请按下文所述逐个退役。

## 颁发机构的轮换与退役

轮换新增一个颁发机构，并把它替换掉的那个留在原处：

```console
$ vault write pki-gmsm/root/rotate/internal common_name="Example Root CA 2026"
Key                 Value
---                 -----
certificate         -----BEGIN CERTIFICATE-----…
issuer_id           4b1d…
previous_issuer_id  c8f1…
```

此后挂载点用新机构签名。旧机构仍然可以通过 `issuer/:ref` 访问，也仍然可以为 `issuer_ref` 指向它
的角色签名；正因如此，在它名下签发的证书在有效期内始终保有自己的颁发机构，以及 `issuer/:ref/crl`
上属于自己的列表。`issuer/:ref/default` 可以把挂载点切回其中任意一个：

```console
$ vault write -f pki-gmsm/issuer/c8f1…/default
```

| 路径 | 用途 |
| --- | --- |
| `root/rotate/:type` | 生成新的自签名颁发机构并用它签名 |
| `POST issuer/:ref` | 修改它的名称、密钥的用途以及它公布的地址 |
| `issuer/:ref/json`、`/pem`、`/der` | 以一份 JSON 文档、PEM 或 DER 形式读取该机构 |
| `issuer/:ref/default` | 把其中一个机构设为正在使用的机构 |
| `issuer/:ref/issue/:role`、`/sign/:role` | 用该机构签发或签名，不论角色指向谁 |
| `DELETE issuer/:ref` | 退役一个机构，前提是它的证书都已过期 |
| `config/ca` | 接收证书、它上面的证书链，以及可选的私钥，或指明持有私钥的提供方 |

退役一个颁发机构会删除它的密钥、缓存的列表、它记录的吊销以及它签发过的证书；此后挂载点改用另一个
机构签名。只要该机构还有未过期的证书，退役就会被拒绝，因为本该报告这些吊销的列表会随之消失。
`DELETE /root` 仍然删除一切，但它会拒绝已经轮换过的挂载点：请逐个退役，直到只剩一个。

`config/ca` 是接收在别处（离线或由其他工具）创建的颁发机构的入口。包中携带证书、它上面的证书，
以及（当挂载点要自己签名时）与之配套的私钥。证书必须是 CA 证书，链上的签名必须首尾相接，包里的
私钥必须就是证书所带的那个；任何一项不符都会在保存之前被拒绝。

```console
$ vault write pki-gmsm/config/ca pem_bundle=@authority.pem
$ vault write pki-gmsm/config/ca pem_bundle=@authority-cert.pem \
    provider=pkcs11 reference=ca-key
```

### 外部签名器

如果密钥不能离开 HSM、PKCS#11 令牌或密钥管理服务，它仍然可以充当挂载点签名用的密钥。只导入证书、
不带私钥，并指明持有私钥的提供方：

```bash
vault write pki-gmsm/config/ca pem_bundle=@authority-cert.pem \
    provider=pkcs11 reference=ca-key
```

reference 是提供方用来找到密钥的任何标识。它会随颁发机构一起记录，每次签名时读取。挂载点在导入时
会向提供方索取公钥，并拒绝与证书不符的密钥，因此不会出现签出的证书只能自证的情况。此后每次签名都
走同一条路径：证书、列表、增量 CRL 以及 OCSP 响应都会送往那台密码设备，私钥从不进入 Vault。

挂载点无法用这样的密钥生成颁发机构，因为它没法让一台设备去创建密钥。密钥和证书由设备生成，再由
`config/ca` 接收。

提供方是一段 Go 实现，因为与设备通信要用设备自带的库。它由嵌入插件的程序在开始提供服务之前注册：

```go
provider := pkcs11.Provider{Module: "/usr/lib/softhsm2.so"}
if err := pki.RegisterSignerProvider("pkcs11", provider); err != nil {
    log.Fatal(err)
}
```

它会拒绝空名称、nil 提供方以及已被占用的名称，这样重复注册同一台设备会变成启动错误，而不是在两者
之间悄悄做出选择。

接口是 `issuerKey`：包含 `crypto.Signer`、`crypto.MessageSigner` 和 `Close`。让外部签名器真正可用
的，是其中的消息签名接口。SM2 签名覆盖的摘要里包含公钥和签名者的标识，所以只拿到别处算好的摘要的
密钥，只能给出无人能校验的签名。构建证书和列表的代码真正需要的是 `Public` 和 `Sign`。

`Close` 是留到以后再加会代价高昂的部分。挂载点每次签名都解析出一个签名器，拿到字节后立即关闭它，
因此令牌的会话或到密钥管理服务的连接不会比需要它的请求活得更久：以池的方式复用会话或连接的提供方，
会在这里收回签名器。被拒绝的签名器同样会被关闭——否则一个返回错误密钥的提供方，每遇到一次被拒绝的
请求就会占住一个会话。关闭失败只会被记录，不会让一个已经拿到签名的请求失败。

接口里没有任何方法携带 context，因为构建证书和列表的代码只把字节交给签名器，并不给截止时间。需要
通过网络通信的提供方应自行设定时限。

本仓库中没有任何代码注册提供方，所以原样构建出来的版本只能用自己持有的密钥签名。值得警惕的故障是
提供方开始返回另一把密钥：挂载点每次签名都会拿公钥与证书核对，不符即拒绝，而不会签发一张无人能验证
的证书。

### 颁发机构的用途

一个颁发机构不止是一张证书：它的密钥能用来做什么、如何处理会比它自己活得还久的证书、它的证书公布
哪些地址，这些都属于它，由 `POST issuer/:ref` 修改。只有请求中出现的字段会变，所以一次只设置其中
一项的写入不会动其余项。

```console
$ vault write pki-gmsm/issuer/c8f1… issuer_name=primary \
    usage=issuing-certificates,crl-signing,ocsp-signing \
    leaf_not_after_behavior=truncate \
    crl_distribution_points=https://ca.example.com/crl
```

`issuer_name` 是此后任何接受 `ref` 的路径用来定位该机构的名称。`usage` 决定它的密钥能做什么：
`issuing-certificates`、`crl-signing` 和 `ocsp-signing`。从未设置过的机构三者皆可，这正是字段出现
之前创建的挂载点还能继续工作的原因；`read-only` 则三者全禁。请求了机构不允许做的事会以 400 拒绝；
响应器则改在协议层返回 `unauthorized`，因为 OCSP 客户端读不到 API 的错误。

`leaf_not_after_behavior` 决定一张会活过颁发机构的证书如何处理。`truncate` 截短并给出警告，是
默认值；`err` 拒绝请求并列出两个日期；`permit` 允许它照原样存在，面向更长寿的上级机构的挂载点需要
这个。

三个地址列表——`issuing_certificates`、`crl_distribution_points` 和 `ocsp_servers`——按列表逐个
覆盖 `config/urls`，持有多个颁发机构的挂载点正是靠它让每张证书指向签发它的那个机构的列表。把某个
列表置空，该项就回到挂载点级别的地址：

```bash
vault write pki-gmsm/issuer/$ISSUER_ID crl_distribution_points=""
```

需要把颁发机构在别处复现时，应当留存的是 `issuer/:ref/json` 这份文档：它包含证书、它上面的证书链，
以及不属于证书的那些设置。`issuer/:ref/pem` 和 `issuer/:ref/der` 只以原始响应体的形式提供证书本身。

## 角色

角色是决定能签发什么的策略。请求只有通过角色校验才会被签名，被拒绝的请求因此不会留下任何证书。

```console
$ vault write pki-gmsm/roles/web allowed_domains=example.com allow_subdomains=true \
    ttl=24h max_ttl=720h
```

`roles/:name` 还支持 `PATCH`。写入与 patch 的区别见[角色名与存储](#角色名与存储)。`roles` 列出
所有名称。

| 分组 | 字段 |
| --- | --- |
| 有效期 | `ttl`（720h）、`max_ttl`（8760h）、`not_before_duration`（向前回填 30s）、`not_after`（本身没有截止时间） |
| 名称 | `allowed_domains`、`allow_bare_domains`、`allow_subdomains`、`allow_glob_domains`、`allow_any_name`、`allow_wildcard_certificates`、`allow_localhost`、`enforce_hostnames`、`require_cn`（开启）、`cn_validations`（`email,hostname`）、`allowed_uri_sans`、`allowed_other_sans`、`allow_ip_sans` |
| 配置 | `policy_identifiers`（无）：证书声明的证书策略 |
| 主题 | `organization`、`ou`、`country`、`locality`、`province`、`street_address`、`postal_code`、`serial_number`（OID 2.5.4.5 的值，不是证书序列号） |
| 用途 | `key_usage`（`DigitalSignature,KeyAgreement`）、`ext_key_usage`、`ext_key_usage_oids`、`server_flag`、`client_flag`、`code_signing_flag`、`email_protection_flag` |
| 存储 | `no_store`、`generate_lease` |
| 签名 | `issuer_ref`（`default`），签发证书时解析为标识或名称 |

名称命中 `allowed_domains` 三种独立模式之一即被接受：`allow_bare_domains` 针对域名本身，
`allow_subdomains` 针对其下的名称，`allow_glob_domains` 则把条目当作 glob 通配模式来解释。
电子邮件地址用域名部分走同样的规则，所以 `user@example.com` 需要 `allow_bare_domains`，而
`user@mail.example.com` 需要 `allow_subdomains`。通配符按整体校验，星号也算在内，因此
`*.example.com` 由 `allow_subdomains` 覆盖，而不是 `allow_bare_domains`。

### 角色名与存储

角色名就是记录所用的存储键，即 `role/<name>`，所以一个名称只对应一份策略。它仅在挂载点内唯一：
其他挂载点中的同名记录与之无关，而且角色名称不会出现在证书里。路径接受
`\w(([\w-.]+)?\w)?`，因此允许字母、数字、`_` 以及中间的 `-` 或 `.`，不允许 `/`；名称区分大小写：
`signing` 与 `Signing` 是两个角色。

写入会整体替换记录，所以只重申一个字段会把其余字段重置为默认值：

```bash
# 错误：角色保留了 key_usage，却丢掉 server_flag、ttl 等设置
vault write pki-gmsm/roles/signing key_usage=DigitalSignature

# 正确：只改动 key_usage
vault patch pki-gmsm/roles/signing key_usage=DigitalSignature
```

对不存在的角色做 patch 是空操作，而不是错误。

### 仅用于签名的证书

只用来签数据、不用于 TLS 的叶子证书不需要主体备用名称（SAN），也不需要 TLS 用途，它的通用名通常
不是主机名：

```bash
vault write pki-gmsm/roles/signing \
    key_usage=DigitalSignature \
    server_flag=false client_flag=false code_signing_flag=true \
    allow_any_name=true enforce_hostnames=false \
    ttl=720h max_ttl=8760h

vault write pki-gmsm/issue/signing common_name="Example Release Signing 2026" \
    exclude_cn_from_sans=true
```

- `key_usage` 去掉默认的 `KeyAgreement`。签名需要 `DigitalSignature`；如需不可否认，可以再加上
  `ContentCommitment`。
- `server_flag=false client_flag=false` 去掉 `serverAuth` 和 `clientAuth`，这样即使对端想把它当作
  TLS 证书使用，它也不是。
- `code_signing_flag=true` 是对应代码签名的扩展用途。若要改为签文档，可以把所有 flag 都关掉，证书
  就完全不带扩展用途，把判断留给依赖方；也可以显式列出用途，包括 RFC 9336 的文档签名 OID
  （`ext_key_usage_oids=1.3.6.1.5.5.7.3.36`）。
- `allow_any_name=true` 取消域名策略。让通用名可以是任意文本的是 `enforce_hostnames=false`：即使
  开了 `allow_any_name`，主机名检查照样执行，所以带空格的名称在关掉它之前会被拒绝。在
  `allow_any_name` 下不会参考 `cn_validations`。
- 在签发调用上加 `exclude_cn_from_sans=true`，通用名就不会进入主体备用名称——否则它会作为 DNS
  名称加进去。

如果密钥位于 HSM 或其他签名器里，改用 `sign/:role` 并提交证书请求，而不是 `issue/:role`，这样私钥
永远不会进入挂载点。

### 证书声明的内容

有三组字段决定证书如何描述自己，它们都不会从周围的信息中推断：

- `policy_identifiers` 是证书声明的证书策略，用点分十进制 OID 表示。没有指定它们的角色，其证书不
  声明任何策略。只写入标识符，因为限定符指向的文档本挂载点无法担保。
- `not_after` 是该角色的证书最晚可以有效的时刻，用 RFC 3339 形式书写。它是截止时间而不是更长的
  有效期：请求超过它的会被截短并给出警告，在它之后发起的请求会被拒绝。颁发机构自身的剩余有效期会
  在其上再收紧一层。
- `allowed_other_sans` 是请求可以索取的 `otherName` 条目，形式为 `OID;form:value`，允许 glob
  模式。请求在 issue 或 sign 调用中用 `other_sans` 说明想要什么，角色决定其中哪些被接受。

```bash
vault write pki-gmsm/roles/staff policy_identifiers=2.23.140.1.2.1 \
    allowed_other_sans="1.3.6.1.4.1.311.20.2.3;utf8:*"

vault write pki-gmsm/issue/staff common_name=alice@example.com \
    other_sans="1.3.6.1.4.1.311.20.2.3;utf8:alice@example.com"
```

形式取 `utf8` 或 `ia5`，由标识符的要求决定；值在写入角色时和索取名称时都会校验。整个条目与模式
匹配，所以标识符、形式和值三者都要对得上。

## 签发与签名

| 路径 | 用途 |
| --- | --- |
| `issue/:role` | 生成 SM2 密钥，并连同证书一起返回 |
| `sign/:role` | 为调用方已持有密钥的请求签名 |
| `issuer/:ref/issue/:role`、`issuer/:ref/sign/:role` | 同上，但使用路径指定的颁发机构 |

两者都接受 `common_name`、`alt_names`、`ip_sans`、`uri_sans`、`other_sans`、`ttl`、
`exclude_cn_from_sans` 和 `format`（`pem`、`der`，或证书附带私钥时用 `pem_bundle`）。`issue` 另有
`private_key_format`（`der` 表示 SEC 1，或 `pkcs8`）和 `key_type`；`sign` 的 `csr` 可以是 PEM 或
base64 编码的 DER，它会校验请求的签名，并拒绝不是 SM2 的密钥。

```console
$ vault write pki-gmsm/issue/web common_name=web.example.com alt_names=api.example.com
```

`alt_names` 中带 `@` 的条目会成为电子邮件地址，其余都是 DNS 名称。除非设置了
`exclude_cn_from_sans`，通用名会被复制到主体备用名称里，因为真正重要的客户端只看 SAN、不看
通用名（CN）。角色决定是否沿用待签名请求中的通用名和名称（`use_csr_common_name`、
`use_csr_sans`），而本次请求中显式写出的值优先。

`issue` 只返回一次私钥，之后只保留证书，除非角色设置了 `no_store`。

路径中带颁发机构的两种形式，无论角色写的是什么都用该机构签名：路径上的 ref 优先于
`role.issuer_ref`。这样就能在没有专门把所有请求钉在某个机构上的角色的情况下，仍然从挂载点已经轮换
掉的那个机构签发证书。

签名请求之间不会排队。证书、列表和 OCSP 响应都在共享读锁下签名，纯签名请求彼此并行而不是一个接一个。
独占写锁的是变更：吊销、轮换、导入或写入颁发机构。

## 证书读取与吊销

| 路径 | 用途 |
| --- | --- |
| `cert/:serial` | 一张已签发的证书，吊销后附带 `revocation_time` 与 `revocation_reason` |
| `certs`（LIST） | 挂载点保存下来的序列号 |
| `certs/revoked`（LIST） | 挂载点吊销过的序列号 |
| `revoke` | 接受 `serial_number` 或 `certificate` 本身，以及 RFC 5280 的 `revocation_reason` |
| `crl` | JSON 形式的 CRL：`certificate`、`number`、`this_update`、`next_update` |
| `crl/pem`、`crl/der` | 同一份 CRL 的原始响应体（`application/pem-encoding`、`application/pkix-crl`） |
| `crl/rotate` | 以下一个编号重建 CRL |
| `crl/delta`、`/delta/pem`、`/delta/der` | 自完整列表以来的变化，JSON 形式中含 `base_number` |
| `crl/rotate-delta` | 以下一个增量编号重建变化 |
| `issuer/:ref/crl`、`/pem`、`/der` | 某个颁发机构的列表，由它自己签名 |
| `issuer/:ref/crl/rotate` | 以该机构自己的编号重建它的列表 |
| `issuer/:ref/crl/delta`、`/delta/pem`、`/delta/der` | 自该机构完整列表以来的变化 |
| `issuer/:ref/crl/rotate-delta` | 重建该机构的变化 |
| `config/urls` | `issuing_certificates`、`crl_distribution_points`、`ocsp_servers` |
| `config/crl` | 列表的 `expiry` 与 `auto_rebuild`，响应器的 `ocsp_expiry` |
| `tidy` | 删除过期的证书与吊销记录 |

序列号是 128 位随机数，以冒号分隔的大写十六进制报告，接受时有无冒号、大小写均可。

吊销原因是记录的一部分，而不是附注：`cert/:serial` 会报告它，列表条目会携带它，响应器也会重复它，
客户端因此能区分密钥泄露和仅仅是被取代的证书。也可以直接提交证书本身，持有 PEM 的调用方不必自己读
出序列号。原因码就是 RFC 5280 的那一组——0、1、2、3、4、5、6、8、9、10——从未分配的 7 会被拒绝。
重复吊销会返回第一次吊销的时间和原因，并给出警告。

CRL 以 DER 形式缓存在存储中，因为 SM2 签名是随机的：每次读取都重建的 CRL 每次签名都不同，客户端
根本无法缓存。写入吊销会把缓存标记为脏，下一次读取时才重建，所以闲置的挂载点不会为无人请求的签名
付出代价。`crl/rotate` 强制重建。`config/crl` 设置列表声明的有效期；其中的 `auto_rebuild=false` 让
读取完全不签名，此时只有 rotate 路径能改变列表。

列表列出客户端仍可能见过的证书，所以已经过期的证书会在下一次签名列表时被排除在外。列表本身因此不会
膨胀：它携带的是仍然有效的那部分证书的吊销，而不是一部历史。条目背后的记录仍然保留，所以即使某个
序列号的条目已经离开列表，`cert/:serial`、`certs/revoked` 和响应器仍然会回答它。

轮换过的挂载点持有多个颁发机构，`crl` 回答的是它当前用来签名的那个。每个机构维护自己的列表，由
`issuer/:ref/crl` 读取，因此轮换之前签发的证书，是用它自己的机构签发的列表来核对的。把
`crl_distribution_points` 指向这种形式，并在轮换之后更新它：

```bash
vault write pki-gmsm/config/urls \
    crl_distribution_points="$VAULT_ADDR/v1/pki-gmsm/issuer/$ISSUER_ID/crl"
```

证书会一直声明签发时所用的地址；只要挂载点还持有该机构，这个地址就始终可用。只有退役该机构才会
带走它的列表——这正是它的证书尚未全部过期时不允许退役的原因。

在每张证书都记录签发机构之前写入的挂载点，保存着一些没有记录机构名的记录。它们属于写入时正在签名的
那个机构；挂载点第一次把指针指向别的机构时，会记下当时正在签名的是哪一个：轮换不会把它们交给接手的
机构。这类证书的吊销依然会进入其客户端下载的那份列表，而在这些证书仍在使用期间，那个机构不会被退役。

`tidy` 同步执行，并回答它删除了什么。它接受 `safety_buffer`（72h）、`tidy_cert_store`（关闭）和
`tidy_revoked_certs`（开启）。列表会自动略过已经过期的证书，但证书记录和吊销记录会一直保留，直到
`tidy` 判定可以删除，所以请把它排进计划任务，而不是手工调用：每天签发的挂载点每晚一次就够，证书
有效期以周计的挂载点每周一次即可。从不 tidy 的挂载点会保留它签发过的每一张证书。

### 增量 CRL

完整列表会随每次吊销而增长，已经持有它的客户端不该为了解一个序列号而重新下载。`crl/delta` 返回自
它所指的完整列表以来的变化，形式与 `crl` 的三种相同。JSON 形式在 `number`、`this_update`、
`next_update` 之外还报告 `base_number`。

列表在增量 CRL 指示器扩展里声明自己的基准，该扩展标记为 critical，读不懂它的客户端就不会把这个增量
当成完整列表。它自己的编号紧随基准的编号，两者因此可以比较；它由同一个机构签名，同样以 DER 缓存。
在轮换过的挂载点上，`issuer/:ref/crl/delta` 是该机构发布的列表的增量，编号与那份列表一样各自独立。

增量在以下情况下于读取时签名：缺失、已经过期、被某次吊销变得过时，或者它所指的完整列表已不再是正在
提供的那一份。最后一种情况正是这个扩展存在的原因：把增量套用到错误的列表上，会让客户端把从未被吊销
的序列号当成已吊销，同时漏掉真正的吊销。

默认情况下，吊销之后读取也会重建完整列表，这能让客户端保持最新，却几乎不给增量留下内容。想节省带宽
的部署改为按计划重建完整列表：在 `config/crl` 里关掉 `auto_rebuild`，需要更新完整列表时调用
`crl/rotate`，其间读取 `crl/delta` 或调用 `crl/rotate-delta`。客户端于是按计划下载完整列表，其间
只取变化。即便如此，过期的完整列表仍会被重新签名，因为客户端不能对一份已无法使用的列表套用增量。

有两点客户端必须接受。相邻的增量会重复完整列表依然缺少的内容，所以同一条目可能出现在多个增量里，
套用两次与套用一次等价。另外，没有任何列表会表示某次吊销被撤回：证书一旦过期，列表就不再列出它，
而此时客户端早已不再接受它，因此 `removeFromCRL` 从不写入。

## 响应器 OCSP

`ocsp` 响应针对本挂载点所签发证书的 RFC 6960 状态查询，响应由签发该证书的机构签名。客户端一次
只问一张证书：

```bash
# DER 请求以 base64 编码，放在写入请求的字段里传递……
curl -s -o answer.der --data-binary "{\"request\": \"$REQUEST\"}" \
  https://vault.example.com/v1/pki-gmsm/ocsp

# ……或者放在读取请求的路径里。
curl -s -o answer.der https://vault.example.com/v1/pki-gmsm/ocsp/$REQUEST
```

响应体类型是 `application/ocsp-response`，状态为 `good`、`revoked` 或 `unknown`。无法回答的请求同样
在 OCSP 协议里给出状态——`malformedRequest`、`internalError` 或 `unauthorized`，对应 HTTP 400、
500、401——这样客户端才能区分“拒绝作答的响应器”和“根本不存在”。`ocsp` 和 `ocsp/*` 不需要认证，
因为检查证书的客户端手里没有这个 Vault 的令牌；这正是该端点的意义。

编码是必需的，这也是插件无法完全照字面遵循协议的唯一一处。RFC 6960 同样允许把请求直接作为 POST 的
请求体，Vault 为内置响应器读取的就是这种形式，但插件拿到的是请求的数据而不是 HTTP 请求本身，所以
DER 请求体永远到不了它这里。base64 形式是插件能够收到的：一个把 DER 直接 POST 到 `ocsp_servers`
地址的现成 OCSP 客户端，需要 Vault 内置的响应器，或者一个先把请求编码的中间层。

一条消息里只有第一个请求会被回答；指明多张证书的消息会被拒绝，而不是只答一半。请求可以指定的摘要
算法有 SHA-1、SHA-256、SHA-384、SHA-512 和 SM3；使用 SM2 机构签发的证书的客户端用的是 SM3。

状态来自挂载点的记录。从未签发过的序列号是 `unknown`。轮换之后，属于签发它的那个机构的证书仍然保持
`good` 或 `revoked`，而在取代它的机构名下则是 `unknown`，针对某个机构记录的吊销永远不会跑到另一个
机构身上。响应把该机构本身列为响应器，因此校验响应的正是签发这张证书的那张机构证书。报告吊销的
响应会携带吊销时间和记录的原因。

响应的有效期由 `config/crl` 决定：`ocsp_expiry` 未写入时是 12 小时，写 0 则不给出下次更新时间，等于
告诉客户端随时可以取到更新的响应。同一个调用也设置列表的 `expiry`，未写入时是 72 小时，写 0 恢复
该默认值。

证书公布的地址来自 `config/urls`：

```bash
vault write pki-gmsm/config/urls ocsp_servers=https://vault.example.com/v1/pki-gmsm/ocsp
```

## 中间颁发机构

第二个挂载点分两步成为第一个的中间 CA。第一个挂载点始终看不到第二个的密钥：

```console
$ vault write pki-gmsm/root/sign-intermediate csr=@intermediate.pem \
    common_name="Example Issuing CA"
$ vault write pki-int/intermediate/set-signed certificate=@signed.pem
```

第二个挂载点上的 `intermediate/generate/internal` 保存密钥并返回 `csr` 和 `key_id`；随后
`intermediate/set-signed` 会校验该证书是 CA 证书、携带待处理请求的公钥、并且由随它提供的证书签名，
通过之后这条链才成为挂载点的颁发机构。`root/sign-intermediate` 会把有效期收窄到签名机构的剩余有效期，
并给出警告。

请求还可以写入中间 CA 所携带的约束：`permitted_dns_domains` 和 `excluded_dns_domains` 取 DNS 名称，
以点开头的条目同时涵盖其下的子域；`permitted_ip_addresses` 和 `excluded_ip_addresses` 取 CIDR 网段。
单独的地址会被拒绝，而不会被当成单个主机，因为两者含义不同。只要写了其中一项，该扩展就标记为
critical，读不懂约束的客户端因此不会接受它下面的证书。

## 与 Vault pki 的差异

| | Vault pki | 本插件 |
| --- | --- | --- |
| 密钥算法 | RSA、ECDSA、Ed25519 | 仅 SM2 |
| 证书签名 | SHA-2 系列 | 仅 `SM2WithSM3` |
| 主体密钥标识符 | 公钥的 SHA-1，RFC 5280 方法 1 | 公钥的 SM3，截断到 160 位 |
| 颁发机构 | 多个，按名称或标识定位，支持轮换与交叉签名 | 多个，按标识或名称定位，支持轮换；不支持交叉签名 |
| 修改颁发机构 | `POST issuer/:ref` 设置名称、`usage`（`issuing-certificates`、`crl-signing`、`ocsp-signing`、`read-only`）、`leaf_not_after_behavior`、`manual_chain`、`revocation_signature_algorithm` 以及它自己的 AIA 与 CRL 地址 | 同一次写入，使用 `issuer_name`、`usage`、`leaf_not_after_behavior` 以及它自己的 AIA、CRL 与 OCSP 地址；没有 `manual_chain` 与 `revocation_signature_algorithm` |
| 指定签名机构 | 在路径上指定：`issuer/:ref/issue`、`/sign`、`/sign-intermediate`、`/sign-self-issued`、`/sign-verbatim`，或通过 `role.issuer_ref` | 在路径上指定：`issuer/:ref/issue/:role`、`/sign/:role`，或通过 `role.issuer_ref`；路径优先于角色 |
| 读取颁发机构 | `issuer/:ref` 的 JSON，以及 `issuer/:ref/pem`、`issuer/:ref/der` | 同样三种，另有当前机构的 `ca`、`ca/pem`；JSON 文档在证书之外还携带设置 |
| 导入颁发机构 | `config/ca`、`issuers/import/bundle` | `config/ca`，作为挂载点的第一个颁发机构 |
| 证书配置 | 角色字段 `not_after`、`policy_identifiers`、`allowed_other_sans`、`allowed_serial_numbers`、`allowed_user_ids`、`csr_extra_names_oids` 和 `basic_constraints_valid_for_non_ca` | `not_after`、`policy_identifiers` 和 `allowed_other_sans`；请求中的主体序列号、用户标识和额外名称没有实现，基本约束始终标记为有效 |
| 签发中间 CA | 名称约束（`permitted_dns_domains`、`excluded_dns_domains`、`permitted_ip_addresses`、`excluded_ip_addresses`）、`key_usage`、`not_before_duration` 和 `enforce_leaf_not_after_behavior` | `csr`、`common_name`、`use_csr_values`、`ttl`、`max_path_length`、四项名称约束和 `format` |
| 吊销 | 按序列号或 PEM 吊销，可带 `revocation_reason`；`revoke-with-key` 改为接收私钥；`LIST certs/revoked` 报告吊销了什么 | 按序列号或 PEM，支持 RFC 5280 定义的原因码；没有 `revoke-with-key`，`LIST certs/revoked` 报告本挂载点吊销了什么 |
| CRL 与 OCSP 有效期 | `config/crl` 设置 `expiry`、`ocsp_expiry`、`disable`、`ocsp_disable`、`auto_rebuild` 和 `max_crl_entries` | 同一个调用设置 `expiry`、`ocsp_expiry` 和 `auto_rebuild`；无法关闭列表或响应器，列表条目数也没有上限 |
| 增量 CRL | `crl/delta`、`/delta/pem`、`/delta/der`、`issuer/:ref/crl/delta` 和 `crl/rotate-delta`，由 `enable_delta` 控制 | 相同的路径，但没有开关：只要有人请求就构建增量 |
| 外部构建的列表 | `issuer/:ref/sign-revocation-list` 为提供的条目签名；`issuer/:ref/resign-crls` 合并列表 | 未实现 |
| 证书中的 URL | `config/urls` 支持 `{{issuer_id}}` 与 `{{cluster_aia_path}}`、按机构覆盖、增量 CRL 地址，以及用 `config/cluster` 设置集群地址 | 挂载点上的三份静态列表，可以在单个机构上分别覆盖；没有模板、没有增量地址、没有集群地址 |
| CA 密钥 | `keys`、`key/:ref`、`config/keys`、仅限 root 的 `keys/:ref/export`，以及需要托管密钥的 `kms` 密钥类型 | 机构的密钥由插件在编译时接入的签名器提供方持有，或随 `config/ca` 导入；没有自己的密钥库、没有导出路径、没有托管密钥 |
| 租约 | 可按证书选择是否生成租约 | 未实现；`generate_lease` 只产生一条警告 |
| `no_store` | 证书不保存在任何地方，也无法按序列号吊销 | 保留元数据，因此序列号仍可吊销 |
| 读取已保存的证书 | `cert/:serial`、`cert/:serial/raw`、`/raw/pem` 和 `cert-metadata/:serial` | `cert/:serial`，其中携带 PEM |
| 清理 | 异步，带 `tidy/:type/status`、`tidy-cancel` 和 `config/auto-tidy` | 同步，并返回它删除了什么 |
| 删除颁发机构 | `DELETE root` 需要 root 令牌 | 任何策略允许写入 `root` 的令牌，且只在挂载点只剩一个机构时 |
| 注册协议 | 开源引擎提供 ACME；EST、CMPv2 和 SCEP 仅在 Vault 企业版 | 无 |
| CRL | 按需重建，缓存在内存 | 以 DER 缓存在存储中，因为签名是随机的 |
| OCSP | `ocsp_enable`，以及读取 DER 请求体的响应器 | 读取 base64 编码请求的响应器，因为插件永远看不到请求体 |

统一 CRL 与 OCSP、外部策略服务和托管密钥属于 Vault 企业版功能；这张表比较的是本插件与开源引擎。
两边都有的路径或字段，行为与 pki 一致，名称也沿用 pki 的写法——上表列出的是缺失或不同的地方，
而不是改了名称的地方。
