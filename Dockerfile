FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
RUN npm install undici --save
COPY server ./server
RUN mkdir -p /app/server/.cache && chown -R node:node /app
ENV NODE_ENV=production \
    PORT=8787
USER node
EXPOSE 8787
CMD ["node", "server/index.mjs"]
