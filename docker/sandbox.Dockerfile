# Base image for sandbox_provider: docker.
#   docker build -t vibeharness-sandbox:latest -f docker/sandbox.Dockerfile .
#
# The sandbox container runs with no network, so the target's own dependencies must be baked in.
# Build a per-project image on top of this one and point docker_image at it:
#   FROM vibeharness-sandbox:latest
#   COPY requirements.txt /tmp/requirements.txt
#   RUN pip install --no-cache-dir -r /tmp/requirements.txt
# (The target's source is not copied in; it is mounted read-only at run time.)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN pip install --no-cache-dir "pytest>=8.0.0" "pytest-cov>=5.0.0" "requests>=2.31.0"
