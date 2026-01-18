# Build Stage
FROM python:3.9-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Build wheel
RUN rm -rf dist/* && pip install build && python -m build

# Run Stage
FROM python:3.9-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy wheel from builder
COPY --from=builder /app/dist/*.whl .

# Install package
RUN pip install *.whl

# Create a user for security
RUN useradd -m secuscan
USER secuscan

ENTRYPOINT ["secuscan"]
