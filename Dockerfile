# =============================================================================
# Build Stage: Compile and package mcpscan wheels
# =============================================================================
FROM python:3.13-slim AS builder

WORKDIR /build

# Install build prerequisites
RUN apt-get update && apt-get install --no-install-recommends -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir build && \
    python -m build --wheel --outdir /wheels

# =============================================================================
# Final Stage: Lean, secure runtime image
# =============================================================================
FROM python:3.13-slim AS final

LABEL org.opencontainers.image.title="mcpscan" \
      org.opencontainers.image.description="Model Context Protocol (MCP) server security posture scanner" \
      org.opencontainers.image.url="https://github.com/ansh-sm/mcpscan" \
      org.opencontainers.image.source="https://github.com/ansh-sm/mcpscan" \
      org.opencontainers.image.licenses="Apache-2.0"

# Create unprivileged user for security isolation
RUN groupadd -g 10001 mcpscan && \
    useradd -u 10001 -g mcpscan -s /bin/sh -m mcpscan

# Install the built wheel from builder stage
COPY --from=builder /wheels /tmp/wheels
RUN pip install --no-cache-dir /tmp/wheels/*.whl && \
    rm -rf /tmp/wheels

# Set up working directory accessible to mcpscan user
WORKDIR /workspace
RUN chown mcpscan:mcpscan /workspace

USER mcpscan

ENTRYPOINT ["mcpscan"]
CMD ["--help"]
