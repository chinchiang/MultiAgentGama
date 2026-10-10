# sandbox_provider／sandbox_node_provider: docker 的 Node 映像（JavaScript／TypeScript 測試）
# Node image for sandbox_provider / sandbox_node_provider: docker (JavaScript / TypeScript tests).
#   docker build -t vibeharness-sandbox-node:latest -f docker/sandbox-node.Dockerfile .
#
# 容器沒有網路，目標自己的相依套件必須已在目標的 node_modules 裡（唯讀掛載在 /work/<name>；CommonJS 靠 NODE_PATH
# 指到那裡，ESM 的裸 specifier 從被匯入的目標檔往上找）。執行時不安裝任何東西。
# Node >= 22.6 提供 TypeScript 目標的型別剝除（只有型別：不支援 enum、namespace、參數屬性、裝飾器）。
# The container runs with no network, so the target's own dependencies must already be in the target's
# node_modules (mounted read-only at /work/<name>; NODE_PATH points there for CommonJS, and ESM bare
# specifiers resolve by walking up from the imported target file). Nothing is installed at run time.
# Node >= 22.6 provides type stripping for TypeScript targets (types only: no enums, namespaces,
# parameter properties or decorators).
#
# 基底映像以多架構 index digest 釘死（供應鏈強化）；升版時 tag 與 digest 一起改（Dependabot 的 docker 生態系會提議）：
# Base image pinned by its multi-arch index digest (supply-chain hardening); bump tag and digest together
# (Dependabot's docker ecosystem proposes bumps):
#   docker buildx imagetools inspect node:22-slim
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392

ENV NODE_ENV=test \
    NODE_OPTIONS=

# 預設非 root（nobody）；harness 執行時也會傳 --user ／ Non-root (nobody) by default; the harness also passes --user at run time
USER 65534:65534
