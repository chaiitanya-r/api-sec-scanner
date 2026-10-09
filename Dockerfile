# Multi-stage production Dockerfile for api-sec-scanner

# ==========================================
# Stage 1: Build the React Dashboard Client
# ==========================================
FROM node:20-alpine AS client-builder

WORKDIR /app/client

# Copy client dependencies and install
COPY client/package*.json ./
RUN npm ci

# Copy client source and build production bundle
COPY client/ ./
RUN npm run build

# ==========================================
# Stage 2: Production Server & CLI Runner
# ==========================================
FROM node:20-alpine AS runner

WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV PORT=5000
ENV HOST=0.0.0.0

# Copy root manifests and install production-only dependencies
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy scanner source, testbed, and config
COPY src/ ./src/
COPY testbed/ ./testbed/
COPY README.md LICENSE* ./

# Copy built frontend assets from client-builder
COPY --from=client-builder /app/client/dist ./client/dist

# Ensure reports directory exists with proper write permissions for node user
RUN mkdir -p /app/reports && chown -R node:node /app

# Switch to unprivileged non-root user for security
USER node

# Expose Web Dashboard (5000) and Mock Testbed (3000)
EXPOSE 5000 3000

# Container healthcheck against /api/health
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/api/health || exit 1

# Default entrypoint starts the Web Dashboard & API Server
CMD ["node", "src/server.js"]
