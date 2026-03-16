FROM cgr.dev/chainguard-private/node:latest

# Install OS packages
RUN apk add --no-cache \
    bash \
    curl \
    ca-certificates \
    openssl \
    tzdata

# Example application setup
WORKDIR /app

COPY . .

CMD ["bash"]
