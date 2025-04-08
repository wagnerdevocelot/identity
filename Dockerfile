# Stage 1: Build the application
FROM golang:1.22-alpine AS builder

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
# -ldflags="-w -s" reduces the size of the binary by removing debug information
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /identity-go .

# Stage 2: Create the final lightweight runtime image
FROM alpine:latest

WORKDIR /app

# Copy only the compiled binary from the builder stage
COPY --from=builder /identity-go /identity-go

# Copy the templates directory from the builder stage's source copy
# The source path is /app/templates because WORKDIR was /app and we did COPY . .
COPY --from=builder /app/templates ./templates

# Expose the port the application listens on
EXPOSE 8080

# Command to run the executable when the container starts
CMD ["/identity-go"] 