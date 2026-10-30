# Build Stage
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production Serving Stage
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s \
  # 127.0.0.1, not localhost: busybox wget resolves localhost to ::1 first and
  # nginx binds IPv4-only here, so the localhost form reports permanently
  # unhealthy even while the site serves fine (same trap as the demo EVM
  # healthcheck).
  CMD wget -qO- http://127.0.0.1:3000/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
