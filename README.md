# JinguiSSL-core

JinguiSSL 系列的低层级算法核心提取目标。

## Intended Scope

- `src/jinguissl/crypto/**`
- `src/jinguissl/compat/**`
- 算法原语
- TLS / SSH / X.509 底层实现
- record / handshake / session-state core
- 后端与性能敏感内部

## Build

```bash
cjpm build
cjpm test
```

Latest verified result: 51 passed, 0 failed.

## Project Status

This is an issue-sized extraction project. Each packet extracts a bounded surface from the live source tree into this sibling target. See internal governance docs for current line state.
