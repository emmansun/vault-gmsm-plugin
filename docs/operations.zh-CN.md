# 运维

[English](operations.md) | 简体中文

两个插件的运行、安装与构建。功能参考见 [transit 引擎](transit.zh-CN.md) 和
[证书颁发机构](pki.zh-CN.md)。

## 目录

- [兼容性](#兼容性)
- [安装](#安装)
  - [从发行版安装](#从发行版安装)
  - [从源码构建](#从源码构建)
- [发布](#发布)
- [运维注意事项](#运维注意事项)
- [开发](#开发)

## 兼容性

| | |
| --- | --- |
| Vault | 2.1.1（CI 中验证）、1.17.3（手工验证） |
| Go | 1.26 或更高版本，仅用于源码构建 |
| 插件协议 | 多路复用 gRPC 插件；注册名必须与二进制文件名一致 |

插件基于 Vault 2.1.1 的模块集构建。两者都是标准的 `logical.TypeLogical` 后端，可以像其他密钥
引擎一样挂载和卸载。

## 安装

### 从发行版安装

每个发行版都会发布各平台的二进制文件以及对应的 `sha256sum`。把适配你的平台和架构的二进制文件
复制到插件目录，然后注册并启用：

```bash
PLUGIN_DIR=/etc/vault/plugins
PLUGIN_NAME=vault-gmsm-plugin          # Windows 上是 vault-gmsm-plugin.exe
CHECKSUM=$(sha256sum "$PLUGIN_DIR/$PLUGIN_NAME" | cut -d' ' -f1)

vault plugin register -sha256="$CHECKSUM" secret "$PLUGIN_NAME"
vault secrets enable -path=gmsm "$PLUGIN_NAME"
```

传给 `vault plugin register` 的名称必须与插件目录中的文件名一致，Windows 上包括 `.exe` 后缀：
Vault 按 `<plugin_directory>/<registered name>` 查找文件，不会去尝试 `vault-plugin-secrets-`
前缀的形式。证书颁发机构（CA）按自己的插件名和挂载路径以同样的方式安装：

```bash
PLUGIN_NAME=pki-gmsm
CHECKSUM=$(sha256sum "$PLUGIN_DIR/$PLUGIN_NAME" | cut -d' ' -f1)

vault plugin register -sha256="$CHECKSUM" secret pki-gmsm
vault secrets enable -path=pki-gmsm pki-gmsm
```

### 从源码构建

```bash
./scripts/build.sh   # 两个插件，linux/amd64 与 windows/amd64，输出到 pkg/<os>_<arch>/
```

每个输出目录旁都有一个 `.sha256sum` 文件，上面 `-sha256` 参数要的正是它。每次构建生成两个
二进制文件：`vault-gmsm-plugin` 对应 transit 引擎，`pki-gmsm` 对应证书颁发机构。文件名就是插件
的注册名，所以两者必须同步。在 Windows 上，`scripts\build.bat` 会在 `plugin\vault-gmsm-plugin.exe`
旁写出 `plugin\plugin.sha256sum`，在 `plugin\pki-gmsm.exe` 旁写出 `plugin\pki-gmsm.sha256sum`。

## 发布

每次发布对应仓库中的一个 tag，两个插件都随它发布：transit 引擎为
`vault-gmsm-plugin-vX.Y.Z-<os>-<arch>`，证书颁发机构为 `pki-gmsm-vX.Y.Z-<os>-<arch>`，各自
旁边都有对应的 `.sha256`。

版本号属于模块而不是某一个插件，这是有意的：两个二进制文件来自同一个 `go.mod` 和同一个提交，
一个只移动了其中一个插件的 tag，对任何查看仓库的人来说都描述了一种从未存在过的状态。代价是
改动其中一个插件也会抬高另一个的版本号，所以两者的差异记录在发行说明里，注明本次改动涉及哪个插件。

## 运维注意事项

- **密钥受 Vault 存储保护。** 密钥的存储条目被标记为需要密封包装，因此启用了密封包装器的企业版
  部署能获得这层保护；插件内部没有额外的包装步骤。
- **`deletion_allowed` 默认关闭。** 在开启之前，`DELETE keys/:name` 会一直失败，这可以避免误删
  把密钥历史一并带走。
- **收敛加密会泄漏相等关系。** 相同的 context 和 nonce 按设计产生相同的密文；nonce 必须在同一
  context 内唯一，否则密文的安全性不再成立。
- **批量请求默认允许部分失败。** 含有坏条目的批次会返回其余结果，并在原地标记失败项；如果调用方
  需要一个非 200 状态码才能察觉，就配合 `partial_failure_response_code` 使用。
- **策略缓存按挂载点独立。** `cache-config` 设置常驻内存的密钥数量，默认不限，最小为 10。
- **密钥材料以明文传输。** `export`、`import` 和 `backup` 会在请求或响应中携带密钥材料，所以中间
  链路必须可信：到 Vault 的 TLS、不记录响应日志、不遗留密钥文件。Vault transit 的包装密钥交换与
  `byok-export` 尚未实现，`exportable` 与 `allow_plaintext_backup` 才决定这些明文通道是否开放。
- **每个挂载点只有一个颁发机构。** 在已有根 CA 的挂载点上再生成一个会被拒绝；
  替换它的唯一途径是 `DELETE pki-gmsm/root`，已签发的证书和缓存的 CRL 会一并删除。
- **CRL 按需签名。** 吊销会把缓存的 CRL 标记为脏，下一次读取时才重建，因此闲置的挂载点不会为无人
  请求的签名付出代价。
- **证书过期后不再出现在吊销列表中。** 列表只列出客户端仍可能见到的证书，所以证书一旦过期，它
  的条目会在下一次重建列表时离开列表，列表不会在两次 tidy 之间持续增长。条目背后的吊销记录仍然
  保留，由 `tidy` 删除：请把它排进计划任务，每天签发就每晚运行一次，证书有效期以周计时就每周
  运行一次，否则挂载点会永久保留签发过的每一张证书。
- **pki 插件中签名可以并行。** 证书、列表和 OCSP 响应都在共享读锁下签名，纯签名请求之间不会排队；
  吊销、轮换或导入才会独占写锁。

## 开发

```
gmsm/                transit 后端、路径与密钥策略（其中一个插件）
pki/                 证书颁发机构后端、路径与名称策略（另一个插件）
main.go              transit 插件的二进制入口
cmd/pki-gmsm/        证书颁发机构插件的二进制入口
internal/testca/     仅供测试的 SM2 CA，用证书请求签发证书链
internal/ocspclient/ 测试与 CI 演练共用的 OCSP 客户端
scripts/ci/sm2ca/    internal/testca 的命令行封装，供 CI 演练使用
scripts/ci/pkicheck/ CI 演练执行的证书与 OCSP 校验
scripts/             构建脚本
```

```bash
go build ./...
go vet ./...
go test ./...
```

`go test ./...` 是自包含的：除非设置了 `VAULT_ADDR` 和 `VAULT_TOKEN`，REST 测试会跳过。要针对真实
挂载点运行：

```bash
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root GMSM_MOUNT=gmsm
go test -count=1 -run TestRESTAPI -v ./gmsm
```

该测试覆盖 CLI 会隐藏的状态码、JSON 字段名和错误响应结构，也就是客户端真正依赖的部分。

持续集成运行三个任务。`build` 运行两个插件的单元测试。`Integration Test` 构建 transit 插件、安装
Vault、启动开发模式服务器、重放 [README](../README.zh-CN.md) 中的演练，再加上证书与 `uid` 相关的
检查，并在同一个服务器上运行 REST 测试。`PKI Integration Test` 对证书颁发机构做同样的事：生成
颁发机构、写入角色、签发并验证证书（用 `scripts/ci/pkicheck`），在证书有效和吊销后各询问一次
响应器，分别读回 CRL 的三种形式，运行 `tidy`，轮换颁发机构，验证被替换的颁发机构仍在发布记录了
该吊销的列表，最后切换回它。
