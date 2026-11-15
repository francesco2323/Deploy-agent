# deploy-agent CLI image (no dashboard: the UI binds loopback by design).
# Local build: docker build -t deploy-agent:dev --build-arg VERSION=dev .
FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
WORKDIR /src
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ARG VERSION=dev
LABEL org.opencontainers.image.title="deploy-agent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/francesco2323/Deploy-agent" \
      org.opencontainers.image.licenses="NOASSERTION"
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
WORKDIR /work
USER 10001:10001
HEALTHCHECK --interval=60s --timeout=5s CMD ["deploy-agent", "--version"]
ENTRYPOINT ["deploy-agent"]
CMD ["--help"]
