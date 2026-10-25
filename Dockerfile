# Use official Node 22 runtime (Node 22.5+ provides built-in node:sqlite)
FROM node:22-slim

# Set working directory inside container
WORKDIR /app

# Enable experimental SQLite for Node 22's built-in node:sqlite module
ENV NODE_OPTIONS="--experimental-sqlite"
ENV NODE_ENV="production"
ENV PORT=3000

# Copy package manifests
COPY package*.json ./

# Install ALL dependencies (including devDependencies like ts-node and typescript)
RUN npm install

# Copy application source code and static assets
COPY . .

# Expose container port
EXPOSE 3000

# Start server using ts-node in transpile-only mode so no build step is required or can fail
CMD ["npx", "ts-node", "--transpile-only", "src/server.ts"]
