FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build

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
