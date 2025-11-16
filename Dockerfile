FROM node:alpine

WORKDIR /app

ARG PORT=3000
ENV PORT=$PORT
EXPOSE $PORT

COPY package.json ./
RUN apk update && \
    apk add --no-cache bash wget curl procps && \
    npm install

COPY app.js ./

ENTRYPOINT [ "node", "app.js" ]
