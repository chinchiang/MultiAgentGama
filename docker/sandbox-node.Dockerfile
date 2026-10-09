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
FROM node:22-slim

ENV NODE_ENV=test \
    NODE_OPTIONS=
