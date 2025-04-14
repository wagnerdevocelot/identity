# Stage 1: Build the application
# Use a specific Alpine version with security patches applied
FROM golang:1.22.0-alpine3.19 AS builder

# Update packages to patch vulnerabilities
RUN apk update && apk upgrade --no-cache

WORKDIR /app

# Copy dependency manifests first to leverage Docker cache
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy the entire source code including templates
# This ensures templates are available in the builder stage if needed,
# and importantly, for copying to the final stage later.
COPY . .

# Build the Go app, compiling all .go files in the current directory
# Stage 2: Create the final lightweight runtime image
FROM gcr.io/distroless/static-debian11:nonroot

WORKDIR /app

# Copy only the compiled binary from the builder stage
COPY --from=builder /identity-go /identity-go

# Copy only the compiled binary from the builder stage
COPY --from=builder /app/identity-go /identity-go
COPY --from=builder /app/templates ./templates

# Expose the port the application listens on
EXPOSE 8080

# Command to run the executable when the container starts
CMD ["/identity-go"] 