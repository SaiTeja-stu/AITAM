# Build context is the REPO ROOT (see render.yaml) so the dashboard can be baked into the server.

# ---- dashboard (React) ----
FROM node:20-alpine AS ui
WORKDIR /ui
COPY cybershield-dashboard/package.json cybershield-dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
COPY cybershield-dashboard/ ./
RUN npm run build

# ---- backend (Spring Boot) ----
FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY cybershield-backend/gradlew cybershield-backend/settings.gradle cybershield-backend/build.gradle ./
COPY cybershield-backend/gradle ./gradle
# the tracked wrapper points at a local (git-ignored) zip; use the official download instead
RUN sed -i 's#^distributionUrl=.*#distributionUrl=https\://services.gradle.org/distributions/gradle-8.14.3-bin.zip#' gradle/wrapper/gradle-wrapper.properties
RUN chmod +x gradlew && ./gradlew --no-daemon dependencies > /dev/null 2>&1 || true
COPY cybershield-backend/src ./src
COPY --from=ui /ui/dist/ ./src/main/resources/static/
RUN ./gradlew --no-daemon bootJar -x test \
 && cp build/libs/$(ls build/libs | grep -v plain | head -1) /app.jar

# ---- run ----
FROM eclipse-temurin:21-jre
RUN useradd -r -u 1001 shield && mkdir -p /data && chown shield /data
USER shield
WORKDIR /app
COPY --from=build /app.jar app.jar
ENV CYBERSHIELD_DB_PATH=/data/cybershield.db \
    CYBERSHIELD_ARCHIVE_DIR=/data/archive \
    JAVA_OPTS="-Xmx340m -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -Xss512k -Djava.security.egd=file:/dev/./urandom"
EXPOSE 8080
ENTRYPOINT ["sh","-c","exec java $JAVA_OPTS -jar app.jar"]
