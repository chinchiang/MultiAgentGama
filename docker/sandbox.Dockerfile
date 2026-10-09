# sandbox_provider: docker 的基底映像 ／ Base image for sandbox_provider: docker.
#   docker build -t vibeharness-sandbox:latest -f docker/sandbox.Dockerfile .
#
# 沙盒容器沒有網路，目標自己的相依套件必須預先裝進映像。
# 以這個映像為基底為每個專案建一個映像，再把 docker_image 指向它：
# The sandbox container runs with no network, so the target's own dependencies must be baked in.
# Build a per-project image on top of this one and point docker_image at it:
#   FROM vibeharness-sandbox:latest
#   COPY requirements.txt /tmp/requirements.txt
#   RUN pip install --no-cache-dir -r /tmp/requirements.txt
#（目標的原始碼不會複製進去，執行時以唯讀方式掛載。）
# (The target's source is not copied in; it is mounted read-only at run time.)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 釘在與 requirements.lock 相同的版本，讓容器行為與 CI 一致。
# 重跑 `uv pip compile --universal requirements.txt -o requirements.lock` 後請同步更新這裡。
# Pinned to the same versions as requirements.lock so the container behaves like CI.
# Re-run `uv pip compile --universal requirements.txt -o requirements.lock` and update here.
RUN pip install --no-cache-dir "pytest==9.1.1" "pytest-cov==7.1.0" "requests==2.34.2"
