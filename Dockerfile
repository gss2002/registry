FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
ARG GO_BUILD_TAGS
RUN go build ${GO_BUILD_TAGS:+-tags="$GO_BUILD_TAGS"} -o /build/registry ./cmd/registry

FROM alpine:latest
WORKDIR /app
COPY --from=builder /build/registry .
COPY --from=builder /app/data/seed_2025_05_16.json /app/data/seed.json
COPY --from=builder /app/internal/docs/swagger.yaml /app/internal/docs/swagger.yaml
# Set the auth method
ENV MCP_REGISTRY_OIDC_ENABLED=true \
    MCP_REGISTRY_OIDC_ISSUER_URL="https://dex.dev.example.com/dex" \
    MCP_REGISTRY_OIDC_CLIENT_ID="mcp-registry-client" \
    MCP_REGISTRY_OIDC_AUDIENCE="mcp-registry-client" \
    MCP_REGISTRY_OIDC_REQUIRED_SCOPES="openid,profile,email" \
    MCP_REGISTRY_AUTH_METHOD="oidc-bearer" \
    ENVIRONMENT="production"



EXPOSE 8080

ENTRYPOINT ["./registry"]
