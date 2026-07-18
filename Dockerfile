FROM node:22-slim

WORKDIR /app

# Copy trustcard
COPY package.json ./
COPY bin/ ./bin/
COPY lib/ ./lib/
COPY test/ ./test/

# Copy rogue servers
COPY rogue-servers/ ./rogue-servers/

# Install dependencies (none needed — zero-dependency project)
RUN npm install --production --ignore-scripts

# Default: run trustcard against all rogue servers
CMD ["sh", "-c", "for level in 1 2 3 4; do echo '=== Level '$level' ==='; node bin/mcp-trustcard.js -- node rogue-servers/level${level}-*.js; echo; done"]
