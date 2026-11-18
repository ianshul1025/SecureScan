# Build Spring Boot JAR
FROM eclipse-temurin:17-jdk-jammy AS build

WORKDIR /build
COPY backend/ ./backend/

RUN chmod +x backend/mvnw \
    && cd backend \
    && ./mvnw -q -DskipTests package

# Runtime: Java + Nmap (required by NmapScanner)
FROM eclipse-temurin:17-jre-jammy

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl \
    && rm -rf /var/lib/apt/lists/* \
    && nmap --version

WORKDIR /app/backend

COPY --from=build /build/backend/target/SecureScan-*.jar ./app.jar
COPY frontend/ /app/frontend/

# application.properties serves static files from file:../frontend/
# Render and similar hosts set PORT; default 8080 for local docker run
ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD sh -c 'curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1'

ENTRYPOINT ["sh", "-c", "exec java -jar app.jar --server.port=${PORT}"]