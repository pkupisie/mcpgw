# syntax=docker/dockerfile:1
FROM node:20-alpine AS build
WORKDIR /app
COPY ../../package.json ../../package-lock.json ./
COPY ../../packages ./packages
COPY ./package.json ./
COPY ./tsconfig.json ./
COPY ./src ./src
RUN npm ci --ignore-scripts && \
    npm -w @mcpgw/shared run build && \
    npm run build

FROM node:20-alpine AS run
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
EXPOSE 3000
CMD ["node", "dist/index.js"]

