# syntax=docker/dockerfile:1

ARG TARGETARCH
# Pinned by digest; update the tag and digest together in a separate change.
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0@sha256:12dd273c196e92aa91542749b8df0996f497f812811abba9e6613b484f681dd0

ARG TARGETARCH
WORKDIR /app

# The release workflow stages the matching Native AOT archive under amd64/ or arm64/.
COPY ${TARGETARCH}/ /app/

ENV ASPNETCORE_URLS=http://0.0.0.0:8866 \
    DARKVAULT_DATA=/data

# Keep the data directory writable by the non-root runtime user and empty on first boot.
RUN mkdir /data && chown 1654:1654 /data

VOLUME ["/data"]
EXPOSE 8866
USER 1654:1654
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 CMD ["/app/DarkVault.Server", "healthcheck"]
ENTRYPOINT ["/app/DarkVault.Server"]
