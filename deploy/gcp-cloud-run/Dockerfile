# ssh-casign on Google Cloud Run: the static service binary on distroless.
# Built by build.sh, which provides ssh-casign-service (static, musl, with
# its own CA roots) and a config/ directory (with config.toml, or empty).
FROM gcr.io/distroless/static-debian12:nonroot
COPY ssh-casign-service /ssh-casign-service
COPY config/ /etc/ssh-casign/
# Cloud Run sets PORT (8080 by default); the service listens on it.
ENV SSH_CASIGN_CONFIG=/etc/ssh-casign/config.toml
USER nonroot
ENTRYPOINT ["/ssh-casign-service"]
