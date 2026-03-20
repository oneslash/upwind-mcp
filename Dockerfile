FROM golang:1.26.1-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w" \
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
