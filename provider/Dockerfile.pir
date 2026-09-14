# Lightweight re-zerve provider image: native `provider-services pir sidecar`.
# Linux docker client comes from docker:cli so `pir serve` can talk to a
# bind-mounted /var/run/docker.sock (host daemon, sibling lease containers).
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o provider-services ./cmd/pir-sidecar
#   docker build -f Dockerfile.pir -t akash-provider-pir:local .
FROM docker:27-cli AS dockercli
FROM ubuntu:noble
COPY --from=dockercli /usr/local/bin/docker /usr/bin/docker
COPY provider-services /usr/bin/provider-services
RUN chmod +x /usr/bin/provider-services /usr/bin/docker
EXPOSE 8443 8444 18765
ENTRYPOINT ["/usr/bin/provider-services"]
CMD ["pir", "sidecar"]
