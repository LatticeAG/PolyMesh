# syntax=docker/dockerfile:1

# Materialize the exact npm archives that a release publishes. The runtime
# stage never imports workspace source: it receives only these named package
# artifacts. This also makes `docker compose up` reproducible before the tag
# has reached the public npm registry.
FROM node:22-slim AS package-artifacts

WORKDIR /workspace

RUN apt-get update \
  && apt-get install --yes --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY packages ./packages
COPY templategen/packages/create-polymesh-app/package.json ./templategen/packages/create-polymesh-app/package.json

RUN npm ci
RUN mkdir -p /artifacts \
  && npm run build --workspace=@latticeag/polymesh-broker \
  && npm run build --workspace=@latticeag/polymesh-client \
  && npm pack --pack-destination /artifacts --workspace=@latticeag/polymesh-broker \
  && npm pack --pack-destination /artifacts --workspace=@latticeag/polymesh-client

# Install the release-shaped archives by their canonical npm package names.
# Transitive production dependencies are resolved in this separate stage, so
# compilers and source code do not reach the runtime image.
FROM node:22-slim AS dependencies

WORKDIR /opt/polymesh

RUN apt-get update \
  && apt-get install --yes --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY --from=package-artifacts /artifacts /artifacts
RUN npm install --omit=dev --no-audit --no-fund --package-lock=false \
  /artifacts/latticeag-polymesh-broker-*.tgz \
  /artifacts/latticeag-polymesh-client-*.tgz

FROM node:22-slim AS runtime

WORKDIR /app
ENV NODE_ENV=production

COPY --from=dependencies /opt/polymesh/node_modules ./node_modules
COPY templategen/docker/entrypoint.js ./entrypoint.js
COPY templategen/docker/service.js ./service.js

# The entrypoint starts as root solely to initialize the exact mounted runtime
# directory, then drops to the image's built-in non-root `node` user before it
# imports any demo code.
RUN mkdir -p /run/polymesh \
  && chown node:node /app /run/polymesh \
  && chmod 0700 /run/polymesh \
  && chmod 0444 /app/entrypoint.js /app/service.js

ENTRYPOINT ["node", "/app/entrypoint.js"]
CMD ["broker"]
