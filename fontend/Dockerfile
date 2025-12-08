# Stage 1: builder
FROM node:22-slim AS builder
ARG MODE=local
ENV MODE=${MODE}
WORKDIR /mywebapp
COPY package*.json ./
RUN npm install
COPY . .
RUN if [ "$MODE" = "prod" ]; then npm run build; else echo "Skipping build"; fi

# Stage 2: local dev
FROM node:22-slim AS local
WORKDIR /mywebapp
COPY --from=builder /mywebapp ./
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# Stage 3: production
FROM nginx:stable-alpine AS prod
COPY --from=builder /mywebapp/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
