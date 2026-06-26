# Minimal container image for CyberShell Copilot.
# CyberShell is an advisory tool: it scores and suggests commands, and never
# executes them. The image runs as a non-root user and ships the packaged
# rules/knowledge base/benchmark.
#
# Build:  docker build -t cybershell-copilot -f Containerfile .
# Run:    docker run --rm cybershell-copilot risk -- "rm -rf /"

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim
LABEL org.opencontainers.image.title="CyberShell Copilot" \
      org.opencontainers.image.description="Offline cybersecurity-aware terminal command risk scorer and guardrails" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/waltr0/smartTerminal"
RUN useradd --create-home --uid 10001 cybershell
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
USER cybershell
WORKDIR /home/cybershell
ENTRYPOINT ["cybershell"]
CMD ["--help"]
