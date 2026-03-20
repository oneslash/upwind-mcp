# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.1

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build

WORKDIR /src

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/upwind-mcp \
    ./cmd/upwind-mcp

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=build /out/upwind-mcp /usr/local/bin/upwind-mcp

ENV UPWIND_REGION=us \
    UPWIND_REQUEST_TIMEOUT=30s \
    UPWIND_MCP_HTTP_ADDR=127.0.0.1:8080 \
    UPWIND_MCP_HTTP_PATH=/mcp

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/upwind-mcp"]
