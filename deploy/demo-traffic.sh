#!/bin/bash
# Demo traffic simulator for NORA registry
# Generates random registry activity for dashboard demo

REGISTRY="http://localhost:4000"
LOG_FILE="/var/log/nora-demo-traffic.log"

# Sample packages to fetch
NPM_PACKAGES=("lodash" "express" "react" "axios" "moment" "underscore" "chalk" "debug")
MAVEN_ARTIFACTS=(
    "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"
    "com/google/guava/guava/31.1-jre/guava-31.1-jre.pom"
    "org/slf4j/slf4j-api/2.0.0/slf4j-api-2.0.0.pom"
)
DOCKER_IMAGES=("alpine" "busybox" "hello-world")

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Random sleep between min and max seconds
random_sleep() {
    local min=$1
    local max=$2
    local delay=$((RANDOM % (max - min + 1) + min))
    sleep $delay
}

# Fetch random npm package
fetch_npm() {
    local pkg=${NPM_PACKAGES[$RANDOM % ${#NPM_PACKAGES[@]}]}
    log "NPM: fetching $pkg"
    curl -s "$REGISTRY/npm/$pkg" > /dev/null 2>&1
}

# Fetch random maven artifact
fetch_maven() {
    local artifact=${MAVEN_ARTIFACTS[$RANDOM % ${#MAVEN_ARTIFACTS[@]}]}
    log "MAVEN: fetching $artifact"
    curl -s "$REGISTRY/maven2/$artifact" > /dev/null 2>&1
}

# Docker push/pull cycle
docker_cycle() {
    local img=${DOCKER_IMAGES[$RANDOM % ${#DOCKER_IMAGES[@]}]}
    local tag="demo-$(date +%s)"

    log "DOCKER: push/pull cycle for $img"

    # Tag and push
    docker tag "$img:latest" "localhost:4000/demo/$img:$tag" 2>/dev/null
    docker push "localhost:4000/demo/$img:$tag" > /dev/null 2>&1

    # Pull back
    docker rmi "localhost:4000/demo/$img:$tag" > /dev/null 2>&1
    docker pull "localhost:4000/demo/$img:$tag" > /dev/null 2>&1

    # Cleanup
    docker rmi "localhost:4000/demo/$img:$tag" > /dev/null 2>&1
}

# Main loop
log "Starting demo traffic simulator"

while true; do
    # Random operation
    op=$((RANDOM % 10))

    case $op in
        0|1|2|3)  # 40% npm
            fetch_npm
            ;;
        4|5|6)    # 30% maven
            fetch_maven
            ;;
        7|8|9)    # 30% docker
            docker_cycle
            ;;
    esac

    # Random delay: 30-120 seconds
    random_sleep 30 120
done
