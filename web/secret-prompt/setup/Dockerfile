FROM node:20.3.1-alpine

ENV NODE_ENV="production"
ENV CHROME_BIN="/usr/bin/chromium-browser"
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD="true"

RUN set -x \
    && apk update \
    && apk add --no-cache \
    chromium \
    dumb-init

WORKDIR /app

ADD --chown=node:node ./app/package*.json /app
RUN npm ci

ADD --chown=node:node ./app /app
RUN chown node:node /app

USER node

ENV FLAG="CCSC{b4cKt1Cks_AnD_iP_4DDr355_m4g1c}"

CMD ["dumb-init", "node", "app.js"]