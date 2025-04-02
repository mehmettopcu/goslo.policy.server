# Use the official Golang image to create a build artifact.
FROM golang:1.22-alpine AS builder

# Install necessary packages
RUN apk add --no-cache gcc musl-dev

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app statically
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o policy-server main.go

# Start a new stage from alpine
FROM alpine:latest

# Install ca-certificates
RUN apk --no-cache add ca-certificates tzdata

RUN mkdir -p /var/log/policy-server && \
    chown nobody:nobody /var/log/policy-server

USER nobody

EXPOSE 8082

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/policy-server /usr/local/bin/policy-server

# Command to run the executable
ENTRYPOINT ["policy-server"]
