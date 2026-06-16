FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

RUN apt-get update \
    && apt-get install -y libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY engine/target/engine-1.0.0.jar engine-1.0.0.jar

CMD ["java", "-jar", "engine-1.0.0.jar", "eth0", "http://ids_backend:8080"]