# deploy-agent CLI image (no dashboard: the UI binds loopback by design).
# Local build: docker build -t deploy-agent:dev --build-arg VERSION=dev .
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="deploy-agent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/francesco2323/Deploy-agent" \
      org.opencontainers.image.licenses="NOASSERTION"
# Pull in the Debian security fix for zlib1g (CVE-2026-85091) that the base image has not rebuilt with yet.
# Becomes a no-op once the base image catches up; the PR image-scan gate tells you when to drop it.
# hadolint ignore=DL3008   (upgrade of an installed package; the fixed version is whatever Debian security ships)
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
WORKDIR /work
USER 10001:10001
HEALTHCHECK --interval=60s --timeout=5s CMD ["deploy-agent", "--version"]
ENTRYPOINT ["deploy-agent"]
CMD ["--help"]
