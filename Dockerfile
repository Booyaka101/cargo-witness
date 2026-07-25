# syntax=docker/dockerfile:1

# ---- Builder stage -------------------------------------------------------
# better-sqlite3 compiles a native addon, so the build stage needs a
# toolchain (python3, make, g++). Keeping this in a separate stage means the
# final image does not carry the compilers.
FROM node:20-slim AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ---- Final stage ---------------------------------------------------------
FROM node:20-slim

ENV NODE_ENV=production
WORKDIR /app

# Bring in the already-compiled production dependencies.
COPY --from=builder /app/node_modules ./node_modules

# Application code.
COPY package.json ./
COPY bin ./bin
COPY src ./src
COPY action.yml ./

ENTRYPOINT ["node", "bin/cargo-witness.js"]
CMD ["--daemon"]
