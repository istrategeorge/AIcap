# syntax=docker/dockerfile:1.7
#
# Multi-stage build: the builder pulls in the Go toolchain, the final image
# carries only the compiled binary + root CA bundle. Distroless "base" gives
# us glibc (lib/pq is CGO-free so we could use "static", but "base" keeps us
# one debug shell away from troubleshooting without re-pushing an image).

ARG GO_VERSION=1.23
FROM golang:${GO_VERSION}-bookworm AS builder
WORKDIR /src

# Dependency layer — cached when go.mod/go.sum don't change, which is every
# build that isn't bumping a package. Keeps iteration fast.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a static binary so distroless/static works too if we
# ever decide to shrink the runtime further. -trimpath + -ldflags strip build
# paths and debug info so the image is reproducible and a few MB smaller.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/aicap \
    .

# --- runtime -----------------------------------------------------------------
FROM gcr.io/distroless/base-debian12:nonroot

# PORT is read at runtime; declaring it here documents the contract and
# lets `docker run` show it in `docker inspect`.
ENV PORT=8080
EXPOSE 8080

WORKDIR /app
COPY --from=builder /out/aicap /app/aicap

# Run as the preconfigured "nonroot" user (uid 65532). Prevents a container
# escape from landing on a root shell, and matches Render / Fly best practice.
USER nonroot:nonroot

ENTRYPOINT ["/app/aicap"]
