# mcp-bastion — image suitable for both regular Docker and AWS Nitro Enclaves.
#
# Build (regular):
#   docker build -t mcp-bastion:0.2.0 .
#
# Build for Nitro Enclave (on a Nitro-enabled EC2 host):
#   docker build -t mcp-bastion:0.2.0 .
#   nitro-cli build-enclave --docker-uri mcp-bastion:0.2.0 \
#     --output-file mcp-bastion.eif
#   nitro-cli run-enclave --cpu-count 2 --memory 2048 \
#     --eif-path mcp-bastion.eif --enclave-cid 16
#
# When run inside the enclave, /attestation returns a Nitro attestation
# document. Outside, it returns a clear "not attested" fallback.

FROM python:3.12-slim AS base

WORKDIR /app

# System deps. liboqs / pqcrypto need a C toolchain at install time on
# slim images; the wheel covers most cases but keep this conservative.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir -e ".[classifier]"

# AWS NSM API — only available + meaningful inside an enclave. Best-effort
# install; the runtime gracefully handles its absence.
RUN pip install --no-cache-dir aws-nitro-enclaves-nsm-api || true

# Default policy: lives outside the image so customers can mount their own.
COPY examples/policy.yaml /etc/mcp-bastion/policy.yaml

EXPOSE 8080
ENTRYPOINT ["mcp-bastion"]
CMD ["up", "--policy", "/etc/mcp-bastion/policy.yaml", \
     "--listen", "0.0.0.0:8080", \
     "--upstream-url", "http://upstream-mcp:9000", "--verbose"]
