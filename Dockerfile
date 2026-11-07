FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build

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
