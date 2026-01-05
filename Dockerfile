FROM golang:1.25-alpine AS build

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/grape ./main.go

FROM alpine:3.19
RUN adduser -D -g '' app
USER app
COPY --from=build /bin/grape /bin/grape
EXPOSE 8080
ENTRYPOINT ["/bin/grape"]
