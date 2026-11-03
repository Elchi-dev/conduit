# conduit-hub container image.
#   docker build -f deploy/hub/Dockerfile -t conduit-hub .
FROM node:22-alpine AS site
WORKDIR /src
RUN corepack enable
COPY docs ./docs
COPY site/package.json site/pnpm-lock.yaml ./site/
RUN cd site && pnpm install --frozen-lockfile
COPY site ./site
RUN cd site && pnpm build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
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
