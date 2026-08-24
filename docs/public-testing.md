# JinguiSSL Core 公开测试面

JinguiSSL Core 不另造一套测试框架。公开复验仍以现有入口为准：

```bash
bash scripts/jinguissl_pre_review.sh <base-ref>
```

省略 `<base-ref>` 时，入口仍会依次运行三类仓库审计、能力与文档 gate、gate 回归测试、
`cjpm build` 和完整 `cjpm test`。提供 base ref 时，还会检查 public API 变更是否同步能力清单、
生成矩阵、README 和对应 manual。

托管 CI 运行同一组底层命令。GitHub Actions 页面公开每个 commit 的 job/step 结果；构建 job
另上传 `jinguissl-public-test-<commit>` artifact，里面只有：

- `provenance.txt`：commit、runner OS/architecture、Cangjie 编译器与 cjpm 版本；
- `build.log`：该 commit 的完整构建日志；
- `test.log`：该 commit 的完整测试日志和最终 TOTAL/PASSED/SKIPPED/ERROR/FAILED 汇总。

artifact 是 CI 证据副本，不是第二套结果数据库。公开结论应同时引用 workflow run、commit、
工具链和最终测试汇总；不能把旧 artifact 叫作当前 `latest`。

## 当前分层与边界

| 测试面 | 当前入口 | 公开结果 | 证据边界 |
| --- | --- | --- | --- |
| 公开仓安全审计 | `jinguissl_ci_audit.sh public` | Actions step 日志 | 检查冲突残留、凭据形态、本机路径和内部目录；不是密码源码安全审计 |
| 托管依赖图与 lock | `hosted-graph`、`dependency-lock` | Actions step 日志 | 检查公开依赖可复验性；不代表依赖本身已安全审计 |
| 能力与文档契约 | capability gate 及其回归测试 | Actions step 日志 | 核对 public API、能力矩阵、README/manual 与限制描述 |
| 构建 | `cjpm build` | job 状态、`build.log` | 证明该 runner 与工具链能构建 |
| 单元与协议回归 | `cjpm test` | job 状态、`test.log` | 本轮接入前基线为 `477/477`；具体一次运行以对应 commit 日志为准 |
| known-answer vectors | Cangjie 测试套内 RFC/NIST/协议向量 | 计入测试总数 | 尚未逐向量输出统一 ID 清单 |
| 负向与 fail-closed | Cangjie 测试套内错误密钥、标签、边界、票据与协议负向 | 计入测试总数 | 证明已写入的拒绝路径，不代表穷尽攻击面 |
| 外部密码向量库 | 尚未接入标准 lane | 无通过声明 | 尚未接入完整 Wycheproof corpus |
| TLS/SSH/QUIC 外部互操作 | 尚未接入标准 lane | 无通过声明 | 不声明 OpenSSL/BoringSSL/浏览器/curl/OpenSSH/HTTP/3 在线互操作通过 |
| fuzz / sanitizer / 故障注入 | 尚未接入标准 lane | 无通过声明 | 普通单元测试不等于模糊测试或内存安全证明 |
| 恒定时与认证 | 尚未接入标准 lane | 无通过声明 | 不声明 constant-time、FIPS 140、商密或第三方安全认证 |
| 打包与发布 | 独立 release gate | 不在测试 job 内 | 测试通过不等于 bundle、publish 或注册表消费成功 |

## 借鉴的大型密码库做法

- [OpenSSL test README](https://github.com/openssl/openssl/blob/master/test/README.md)
  把完整测试、选择性测试、失败复现和随机种子写成公开契约。JinguiSSL 当前复用一个权威入口，
  不在其上重复维护命令清单。
- [BoringSSL BUILDING](https://github.com/google/boringssl/blob/main/BUILDING.md)
  与 [SSL test README](https://boringssl.googlesource.com/boringssl/+/HEAD/ssl/test/README.md)
  区分 C/C++ 测试和 TLS 黑盒 runner。JinguiSSL 同样不把本地协议回归包装成第二实现互操作。
- [rustls](https://github.com/rustls/rustls) 将主测试、Bogo、OpenSSL tests、fuzz 和
  connect tests 分为不同通道。JinguiSSL 在对应通道真正接入前保留明确的“未覆盖”。
- [Project Wycheproof](https://github.com/C2SP/wycheproof) 用带 schema 的 JSON 向量覆盖
  已知攻击与边界。JinguiSSL 后续若接入，应固定上游 revision、保留 vector ID，并独立报告
  valid/invalid/acceptable 数量，不能只复制零散十六进制样例。

这些参考只用于测试结构，不构成与上述项目安全成熟度、审计历史或互操作覆盖等同的声明。
