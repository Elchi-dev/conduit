# conduit-hub container image.
#   docker build -f deploy/hub/Dockerfile -t conduit-hub .
FROM --platform=$BUILDPLATFORM node:22-alpine AS site
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@10.28.0 --activate
COPY docs ./docs
COPY api ./api
COPY scripts ./scripts
COPY site/package.json site/pnpm-lock.yaml ./site/
RUN cd site && pnpm install --frozen-lockfile
COPY site ./site
# The marketplace pages share the app's readme renderer.
COPY web/src/lib/markdown.ts ./web/src/lib/markdown.ts
RUN cd site && pnpm build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X github.com/elchi-dev/conduit/internal/version.Version=${VERSION}" \
    -o /out/conduit-hub ./cmd/conduit-hub

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/conduit-hub /usr/local/bin/conduit-hub
COPY --from=site /src/site/dist /site
# SQLite lives here when CONDUIT_HUB_DB is a path; mount a volume.
WORKDIR /data
ENV CONDUIT_HUB_LISTEN=:7700 CONDUIT_HUB_DB=/data/hub.db CONDUIT_HUB_SITE_DIR=/site
EXPOSE 7700
USER nonroot
ENTRYPOINT ["/usr/local/bin/conduit-hub"]
