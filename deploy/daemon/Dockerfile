# conduitd container image: the daemon with the web app built in.
#   docker build -f deploy/daemon/Dockerfile -t conduitd .
#   docker run -d -p 127.0.0.1:7600:7600 -v conduit:/data conduitd
FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@10.28.0 --activate
COPY web/package.json web/pnpm-lock.yaml ./web/
RUN cd web && pnpm install --frozen-lockfile
COPY web ./web
COPY api ./api
RUN cd web && pnpm build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./internal/ui/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags ui -trimpath \
    -ldflags "-s -w -X github.com/elchi-dev/conduit/internal/version.Version=${VERSION}" \
    -o /out/conduitd ./cmd/conduitd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/conduitd /usr/local/bin/conduitd
# Everything the daemon keeps (database, vault, notes) lives in /data.
WORKDIR /data
VOLUME ["/data"]
# The image is replaced to update, so the daemon's self-updater stays off.
# CONDUIT_ALLOWED_HOSTS lists names you reach the daemon by besides IP
# addresses and localhost (e.g. conduit.example.com behind a proxy).
ENV CONDUIT_MANAGED=container CONDUIT_UPDATE_CHECK=off
EXPOSE 7600
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/usr/local/bin/conduitd", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/conduitd"]
CMD ["-listen", "0.0.0.0:7600", "-data", "/data"]
