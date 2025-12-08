#############################
# Stage 1: Builder
#############################
FROM node:22-slim AS builder

ARG MODE=local
ENV MODE=${MODE}

WORKDIR /mywebapp

COPY package*.json ./
RUN npm install

COPY . .

# Build only in production mode
RUN if [ "$MODE" = "prod" ]; then npm run build; else echo "Skipping build"; fi


#############################
# Stage 2: Development (local)
#############################
FROM node:22-slim AS local

WORKDIR /mywebapp
COPY --from=builder /mywebapp ./

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]


#############################
# Stage 3: Production
#############################
FROM nginx:stable-alpine AS prod

# dist exists only in prod mode
COPY --from=builder /mywebapp/dist /usr/share/nginx/html

COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
