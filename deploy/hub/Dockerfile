# conduit-hub container image.
#   docker build -f deploy/hub/Dockerfile -t conduit-hub .
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
# SQLite lives here when CONDUIT_HUB_DB is a path; mount a volume.
WORKDIR /data
ENV CONDUIT_HUB_LISTEN=:7700 CONDUIT_HUB_DB=/data/hub.db
EXPOSE 7700
USER nonroot
ENTRYPOINT ["/usr/local/bin/conduit-hub"]
