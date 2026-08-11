# ─────────────────────────────
# Base image
# ─────────────────────────────
FROM node:22-alpine AS base

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY prisma ./prisma
RUN npx prisma generate


# ─────────────────────────────
# Development (MAIN LOCAL USE)
# ─────────────────────────────
FROM base AS development

ENV NODE_ENV=development

COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"]


# ─────────────────────────────
# Test stage (optional)
# ─────────────────────────────
FROM base AS test

ENV NODE_ENV=test

COPY . .

CMD ["npm", "test"]
