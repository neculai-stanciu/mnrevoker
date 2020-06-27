FROM openjdk:14-alpine
COPY target/mnrevoker-*.jar mnrevoker.jar
EXPOSE 8080
CMD ["java", "-Dcom.sun.management.jmxremote", "-Xmx128m", "-jar", "mnrevoker.jar"]
