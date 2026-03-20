set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

image := "upwind-mcp:local"
binary := "dist/upwind-mcp"

default:
    @just --list

fmt:
    go fmt ./...

test:
    go test ./...

vuln:
    govulncheck ./...

build:
    mkdir -p dist
    go build -trimpath -o {{binary}} ./cmd/upwind-mcp

run:
    go run ./cmd/upwind-mcp

run-http:
    test -n "${UPWIND_MCP_HTTP_BEARER_TOKEN:-}"
    go run ./cmd/upwind-mcp serve-http

docker-build image_override=image:
    docker build --tag {{image_override}} .

docker-run-stdio image_override=image:
    docker run --rm -i \
      --init \
      --read-only \
      --tmpfs /tmp:rw,noexec,nosuid,size=64k \
      --cap-drop=ALL \
      --security-opt=no-new-privileges \
      --pids-limit=64 \
      -e UPWIND_REGION \
      -e UPWIND_BASE_URL \
      -e UPWIND_ORGANIZATION_ID \
      -e UPWIND_CLIENT_ID \
      -e UPWIND_CLIENT_SECRET \
      -e UPWIND_REQUEST_TIMEOUT \
      {{image_override}}

docker-run image_override=image host_port="8080":
    test -n "${UPWIND_MCP_HTTP_BEARER_TOKEN:-}"
    docker run --rm \
      --init \
      --read-only \
      --tmpfs /tmp:rw,noexec,nosuid,size=64k \
      --cap-drop=ALL \
      --security-opt=no-new-privileges \
      --pids-limit=64 \
      -p 127.0.0.1:{{host_port}}:8080 \
      -e UPWIND_REGION \
      -e UPWIND_BASE_URL \
      -e UPWIND_ORGANIZATION_ID \
      -e UPWIND_CLIENT_ID \
      -e UPWIND_CLIENT_SECRET \
      -e UPWIND_REQUEST_TIMEOUT \
      -e UPWIND_MCP_HTTP_PATH \
      -e UPWIND_MCP_HTTP_BEARER_TOKEN \
      -e UPWIND_MCP_HTTP_ADDR=0.0.0.0:8080 \
      {{image_override}} serve-http --public-bind

clean:
    rm -rf dist
