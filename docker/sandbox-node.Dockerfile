# Node image for sandbox_provider / sandbox_node_provider: docker (JavaScript / TypeScript tests).
#   docker build -t vibeharness-sandbox-node:latest -f docker/sandbox-node.Dockerfile .
#
# The container runs with no network, so the target's own dependencies must already be in the target's
# node_modules (mounted read-only at /work/<name>; NODE_PATH points there for CommonJS, and ESM bare
# specifiers resolve by walking up from the imported target file). Nothing is installed at run time.
# Node >= 22.6 provides type stripping for TypeScript targets (types only: no enums, namespaces,
# parameter properties or decorators).
FROM node:22-slim

ENV NODE_ENV=test \
    NODE_OPTIONS=
