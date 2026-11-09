FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/atlas ./cmd/atlas

FROM gcr.io/distroless/static-debian13:nonroot

WORKDIR /
COPY --from=build --chown=65532:65532 /out/atlas /atlas

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/atlas"]
