# Vault GMSM 插件

[English](README.md) | 简体中文

[![CI](https://github.com/emmansun/vault-gmsm-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/vault-gmsm-plugin/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/emmansun/vault-gmsm-plugin.svg)](https://pkg.go.dev/github.com/emmansun/vault-gmsm-plugin)
[![Go version](https://img.shields.io/github/go-mod/go-version/emmansun/vault-gmsm-plugin)](go.mod)
[![Release](https://img.shields.io/github/v/release/emmansun/vault-gmsm-plugin?sort=semver)](https://github.com/emmansun/vault-gmsm-plugin/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

这是面向国密（SM）算法的两个 [HashiCorp Vault](https://www.vaultproject.io/) 插件：

- **`vault-gmsm-plugin`**：transit 密钥引擎，提供 SM4-GCM 加解密与 SM2 签名。密钥既可以在 Vault
  内部生成，也可以导入现有密钥材料；除非把密钥标记为可导出，否则它不会离开挂载点。请求与响应
  的数据结构沿袭 Vault 1.14 的 transit 密钥引擎，因此现有的 transit 工具、策略和客户端库只需
  调整挂载路径即可继续使用。
- **`pki-gmsm`**：同一套算法下的证书颁发机构（CA），负责生成 SM2 密钥、用 `SM2WithSM3` 签发
  X.509 证书、发布 CRL 与增量 CRL，并响应 OCSP 状态查询。密钥可以留在挂载点内，也可以继续放在
  硬件安全模块（HSM）或密钥管理服务里，通过插件在编译时接入的签名器提供方访问。它之所以单独
  挂载，是因为 Vault 规定一个挂载只能绑定一个插件，而 CA 的生命周期又与 transit 密钥完全不同。

## 能力

| 挂载点 | 密钥类型 | 支持的操作 |
| --- | --- | --- |
| `gmsm` | `sm4-gcm96`（默认） | 加密、解密、`rewrap`、数据密钥、密钥派生、收敛加密、附加数据 |
| `gmsm` | `sm2` | 加密、解密、`rewrap`、数据密钥、签名、验签、证书请求 |
| `gmsm` | `hmac` | 仅 HMAC-SM3，密钥长度为 32 至 512 字节 |
| `pki-gmsm` | `sm2` | 根 CA 与中间 CA、轮换与导入、带名称策略的角色、`issue`、`sign`、吊销、CRL 与增量 CRL、OCSP、`tidy`，以及用于 CA 密钥的外部签名器 |

HMAC-SM3 与密钥类型无关，每个密钥版本都能使用，所以 `sm2` 密钥同样可以计算并校验 HMAC。较早的
类型名 `ecdsa-sm2` 在所有接受 `type` 的路径上仍然可用，用它创建的密钥会报告为 `sm2`。三种
transit 密钥类型都支持导入密钥材料。

不支持的组合一律拒绝，而不是做半成品：`sm4-cmac` 密钥在创建时即失败；用不支持加密、解密或
签名的密钥类型执行相应操作同样会被拒绝。

## 安装

把对应平台和架构的发行版二进制文件放进 Vault 的插件目录，然后注册并启用。传给
`vault plugin register` 的名称必须与文件名完全一致，Windows 上还包括 `.exe` 后缀：

```bash
vault plugin register -sha256="$(sha256sum /etc/vault/plugins/vault-gmsm-plugin | cut -d' ' -f1)" \
  secret vault-gmsm-plugin
vault secrets enable -path=gmsm vault-gmsm-plugin

vault plugin register -sha256="$(sha256sum /etc/vault/plugins/pki-gmsm | cut -d' ' -f1)" \
  secret pki-gmsm
vault secrets enable -path=pki-gmsm pki-gmsm
```

源码构建、校验和文件、Windows 构建脚本、支持的 Vault 与 Go 版本，以及运维注意事项，见
[运维](docs/operations.zh-CN.md)。

## 快速开始

下面的演示在 Vault 开发模式服务器上进行：

```bash
# Vault 2.x 启动时会探测 -dev-plugin-dir 下的每个二进制，只要有一个不是数据库插件就
# 直接退出，所以先建一个空目录，等服务器起来再把二进制复制进去。
mkdir -p ./plugins
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./plugins

# 另开一个终端；把复制命令的来源改成二进制实际所在的位置
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
cp pkg/linux_amd64/vault-gmsm-plugin pkg/linux_amd64/pki-gmsm ./plugins/
for name in vault-gmsm-plugin pki-gmsm; do
  vault plugin register -sha256="$(sha256sum ./plugins/$name | cut -d' ' -f1)" secret "$name"
done
vault secrets enable -path=gmsm vault-gmsm-plugin
vault secrets enable -path=pki-gmsm pki-gmsm
```

用 SM4-GCM 加密。CLI 不会替你补 base64，所以 `encrypt` 的输入必须已经是 base64：

```console
$ vault write -f gmsm/keys/mykey
Success! Data written to: gmsm/keys/mykey

$ vault write gmsm/encrypt/mykey plaintext="$(printf 'my secret data' | base64)"
Key            Value
---            -----
ciphertext     vault:v1:9J0YlZbF8kQ0dCk8X1sYz1r6FjJ2mQ4lZ0dU6T7hE2c=
key_version    1

$ vault write gmsm/decrypt/mykey ciphertext=vault:v1:9J0YlZbF8kQ0dCk8X1sYz1r6FjJ2mQ4lZ0dU6T7hE2c=
Key         Value
---         -----
plaintext   bXkgc2VjcmV0IGRhdGE=
```

密文与生成它的密钥版本绑定。`rotate` 新增一个版本，`rewrap` 把已有密文迁移到最新版本，全程不
暴露明文：

```console
$ vault write -f gmsm/keys/mykey/rotate
$ vault read -field=latest_version gmsm/keys/mykey
2

$ vault write -field=ciphertext gmsm/rewrap/mykey \
    ciphertext=vault:v1:9J0YlZbF8kQ0dCk8X1sYz1r6FjJ2mQ4lZ0dU6T7hE2c=
vault:v2:oQ7Xb2cR4mN0yY8sK1pL5vT3jH6gF9dA2sE4rU8iO0k=
```

从 CA 签发一张证书：

```console
$ vault write pki-gmsm/root/generate/internal common_name="Example Root CA" ttl=87600h
$ vault write pki-gmsm/roles/web allowed_domains=example.com allow_subdomains=true \
    ttl=24h max_ttl=720h
$ vault write pki-gmsm/issue/web common_name=web.example.com alt_names=api.example.com
```

## 文档

README 与文档都提供中英文两个版本，下表是中文版：

| 文档 | 内容 |
| --- | --- |
| [Transit 引擎](docs/transit.zh-CN.md) | 密钥类型、接口参考（keys、encrypt、sign、HMAC、export）、证书请求、密钥导入，以及本挂载与 transit 的差异 |
| [证书颁发机构](docs/pki.zh-CN.md) | 颁发机构的生成、轮换、退役与导入，角色与名称策略，签发与签名，吊销，CRL 与 OCSP 响应器，中间 CA，以及本插件与 pki 的差异 |
| [运维](docs/operations.zh-CN.md) | 兼容性、详细安装步骤、运维注意事项、源码结构、开发命令与 CI 任务 |

## 许可证

这两个插件以 MIT 许可证发布，见 [LICENSE](LICENSE)。

transit 插件的请求和响应字段结构沿用 HashiCorp Vault 的 transit 密钥引擎，该引擎在 1.14.0 及之前
的版本以 MPL-2.0 发布。因此 `gmsm/` 中源自这些版本的部分同样可以按 MPL-2.0 使用。该仓库 1.15.0
及之后的版本改为 BUSL-1.1，本项目有意不把它们作为来源。

证书颁发机构对同一个仓库的 PKI 密钥引擎遵循同样的规则：路径、字段和拒绝方式都以其为范本。`pki/`
中任何源自 MPL-2.0 版本的部分同样可以按 MPL-2.0 使用，没有使用任何来自 BUSL-1.1 版本的代码，
而包本身与本仓库其余部分一样以 MIT 许可证发布。
