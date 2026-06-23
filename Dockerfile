FROM node:22-alpine

WORKDIR /app

# 复制 server 和 parser
COPY server.js sub-converter-parser.js ./

# 可选：复制本地规则配置
COPY Clash/ ./Clash/

EXPOSE 25600

CMD ["node", "server.js"]
