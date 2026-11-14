# ssh-casign on AWS Lambda: the service as an ordinary HTTP server, with the
# Lambda Web Adapter (an extension) translating Lambda events to HTTP.
# Built by build.sh, which provides ssh-casign-service (static, musl) and a
# config/ directory (with config.toml, or empty) in the build context.
ARG ADAPTER_VERSION=0.9.1
FROM public.ecr.aws/awsguru/aws-lambda-adapter:${ADAPTER_VERSION} AS adapter

FROM public.ecr.aws/lambda/provided:al2023
COPY --from=adapter /lambda-adapter /opt/extensions/lambda-adapter
# The provided runtime starts /var/runtime/bootstrap.
COPY ssh-casign-service /var/runtime/bootstrap
COPY config/ /var/task/
WORKDIR /var/task
# The service listens on PORT; the adapter forwards to AWS_LWA_PORT. Not 8080:
# the local runtime interface emulator uses that.
ENV PORT=8000 \
    AWS_LWA_PORT=8000 \
    AWS_LWA_READINESS_CHECK_PATH=/.well-known/ssh-casign \
    SSH_CASIGN_CONFIG=/var/task/config.toml
CMD ["ssh-casign"]
