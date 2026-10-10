FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
# the panel is the api only, the web interface is built from ./frontend
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X frostbite/internal/metrics.Version=${VERSION}" -o /out/panel ./cmd/panel

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/panel ./panel
RUN mkdir -p /app/data
VOLUME ["/app/data"]
EXPOSE 8080
ENTRYPOINT ["./panel"]
