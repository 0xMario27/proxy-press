FROM node:22-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git && \
    git clone --depth 1 https://github.com/CareyWang/sub-web.git . && rm -rf .git
COPY src/config/remote-configs.js /app/src/config/remote-configs.js
COPY src/views/Subconverter.vue /app/src/views/Subconverter.vue
COPY .env.production /app/.env.production
RUN npm install --legacy-peer-deps && npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
