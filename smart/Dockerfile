FROM python:3.12-alpine

WORKDIR /app

# 复制 smart 服务和转换脚本
COPY server.py to_provider.py ./

EXPOSE 25600
CMD ["python3", "server.py"]
