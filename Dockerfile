# syntax=docker/dockerfile:1
# One image, two binaries: chautari (control plane + CLI) and mock-llm (the
# offline provider the demo and tests use). No ENTRYPOINT: Compose, Helm and
# ECS name the binary in their command.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/chautari ./cmd/chautari \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/mock-llm ./cmd/mock-llm \
 && mkdir -p /out/gateway

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="chautari" \
      org.opencontainers.image.description="The open AI control plane" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/lukelittle/chautari"
COPY --from=build /out/chautari /out/mock-llm /usr/local/bin/
# The shared data plane config directory. A named volume mounted here starts
# with this ownership, so the non-root control plane can write the config.
COPY --from=build --chown=65532:65532 /out/gateway /gateway
USER 65532:65532
EXPOSE 8080
CMD ["chautari", "serve"]
