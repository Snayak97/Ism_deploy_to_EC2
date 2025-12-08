# Base image
FROM node:22-slim

# Build argument - default is "local"
ARG MODE=local

# Set env so React/Vite can read the value inside container
ENV MODE=${MODE}

WORKDIR /mywebapp

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the project
COPY . .

# -----------------------------
# Production Build
# -----------------------------
RUN if [ "$MODE" = "prod" ]; then \
      echo "Building production build..." && \
      npm run build; \
    else \
      echo "Skipping build for local mode"; \
    fi

# Expose dev server port (local)
EXPOSE 5173

# Default run command
CMD if [ "$MODE" = "prod" ]; then \
      echo "Starting production preview server..." && \
      npm run preview -- --host 0.0.0.0; \
    else \
      echo "Starting Vite dev server (local)..." && \
      npm run dev -- --host 0.0.0.0; \
    fi
