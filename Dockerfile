ARG GO_VERSION=1.26
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
	-trimpath \
	-ldflags="-s -w \
	-X github.com/colzphml/pkce_istio_external/internal/version.Version=${VERSION} \
	-X github.com/colzphml/pkce_istio_external/internal/version.Commit=${COMMIT} \
	-X github.com/colzphml/pkce_istio_external/internal/version.BuildDate=${BUILD_DATE}" \
	-o /out/authservice ./cmd/authservice

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/authservice /authservice
EXPOSE 8080 9090
ENTRYPOINT ["/authservice"]
