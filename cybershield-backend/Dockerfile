# ---- build ----
FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY gradlew settings.gradle build.gradle ./
COPY gradle ./gradle
# the tracked wrapper points at a local (git-ignored) zip; use the official download instead
RUN sed -i 's#^distributionUrl=.*#distributionUrl=https\://services.gradle.org/distributions/gradle-8.14.3-bin.zip#' gradle/wrapper/gradle-wrapper.properties
RUN chmod +x gradlew && ./gradlew --no-daemon dependencies > /dev/null 2>&1 || true
COPY src ./src
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
    JAVA_OPTS="-Xmx350m -XX:+UseSerialGC"
EXPOSE 8080
ENTRYPOINT ["sh","-c","exec java $JAVA_OPTS -jar app.jar"]
