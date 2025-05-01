FROM node:alpine

WORKDIR /app

COPY server.js package.json /app/

ARG PORT=${PORT:-'3000'}
EXPOSE $PORT

RUN apk update && \
    apk add --no-cache bash wget curl procps zsh && \
    npm install

HEALTHCHECK --interval=2m --timeout=30s CMD curl --fail http://localhost/healthcheck || exit 1

ENTRYPOINT [ "node", "/app/server.js" ]
