FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:24-alpine AS production-deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:24-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=production-deps --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json ./
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node server ./server
RUN mkdir -p /app/server/data && chown -R node:node /app/server
USER node
EXPOSE 8787
CMD ["node", "server/index.js"]
