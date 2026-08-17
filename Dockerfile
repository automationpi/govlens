# ---- build stage ----
# Runs on the BUILD platform and cross-compiles to the TARGET platform, so
# multi-arch (amd64 + arm64) builds are fast and don't need QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static, CGO-free binaries so they run on distroless/static and cross-compile cleanly.
ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -trimpath -ldflags="-s -w" -o /out/web     ./cmd/web
RUN go build -trimpath -ldflags="-s -w" -o /out/collect ./cmd/collect
RUN go build -trimpath -ldflags="-s -w" -o /out/ingest  ./cmd/ingest
RUN go build -trimpath -ldflags="-s -w" -o /out/mcp    ./cmd/mcp
RUN go build -trimpath -ldflags="-s -w" -o /out/remediator ./cmd/remediator
RUN go build -trimpath -ldflags="-s -w" -o /out/grantworker ./cmd/grantworker
RUN go build -trimpath -ldflags="-s -w" -o /out/govlensd ./cmd/govlensd

# ---- runtime stage (distroless, nonroot) ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/web     /web
COPY --from=build /out/collect /collect
COPY --from=build /out/ingest  /ingest
COPY --from=build /out/mcp    /mcp
COPY --from=build /out/remediator /remediator
COPY --from=build /out/grantworker /grantworker
COPY --from=build /out/govlensd /govlensd
EXPOSE 8080
USER nonroot:nonroot
# Default: the all-in-one launcher — runs the whole stack from one config file
# against your own Postgres. Override the entrypoint to run a single component
# (the dev docker-compose does this for web/ingest/remediator/grantworker).
ENTRYPOINT ["/govlensd"]
