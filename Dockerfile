FROM node:alpine

WORKDIR /app

COPY app.js package.json /app/

RUN apk update && \
    apk add --no-cache bash wget curl procps && \
    npm install

CMD ["npm", "start"]
