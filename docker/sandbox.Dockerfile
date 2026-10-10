# sandbox_provider: docker 的基底映像 ／ Base image for sandbox_provider: docker.
#   docker build -t vibeharness-sandbox:latest -f docker/sandbox.Dockerfile .
#
# 沙盒容器沒有網路，目標自己的相依套件必須預先裝進映像。
# 以這個映像為基底為每個專案建一個映像，再把 docker_image 指向它：
# The sandbox container runs with no network, so the target's own dependencies must be baked in.
# Build a per-project image on top of this one and point docker_image at it:
#   FROM vibeharness-sandbox:latest
#   USER root
#   COPY requirements.txt /tmp/requirements.txt
#   RUN pip install --no-cache-dir -r /tmp/requirements.txt
#   USER 65534:65534
# （這個映像預設以 nobody 執行，安裝時要先切回 root，裝完再切回來。）
# (This image runs as nobody by default: switch to root for the install and back afterwards.)
#（目標的原始碼不會複製進去，執行時以唯讀方式掛載。）
# (The target's source is not copied in; it is mounted read-only at run time.)
#
# 基底映像以多架構 index digest 釘死（供應鏈強化）；升版時 tag 與 digest 一起改（Dependabot 的 docker 生態系會提議）：
# Base image pinned by its multi-arch index digest (supply-chain hardening); bump tag and digest together
# (Dependabot's docker ecosystem proposes bumps):
#   docker buildx imagetools inspect python:3.12-slim   （或 registry 回應的 docker-content-digest 標頭 ／ or the registry's docker-content-digest header）
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 以雜湊釘在與 requirements.lock 相同的版本，讓容器行為與 CI 一致。
# 重新產生 requirements.lock（見其檔頭）後，用 docker/sandbox-requirements.in 檔頭的指令重新產生這份雜湊鎖定檔。
# Hash-pinned to the same versions as requirements.lock so the container behaves like CI.
# After regenerating requirements.lock (see its header), regenerate the hashed lock with the command in the
# header of docker/sandbox-requirements.in.
COPY docker/sandbox-requirements.txt /tmp/sandbox-requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/sandbox-requirements.txt \
    && rm /tmp/sandbox-requirements.txt

# 預設非 root。harness 執行時也會傳 --user（主機 uid；harness 以 root 執行時為 nobody），
# 所以這只影響以其他方式執行這個映像的情況。
# Non-root by default. The harness also passes --user at run time (the host uid, or nobody when the
# harness runs as root), so this only matters when the image is run some other way.
USER 65534:65534
