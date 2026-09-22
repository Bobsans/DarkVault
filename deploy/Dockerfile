# syntax=docker/dockerfile:1

ARG TARGETARCH
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0

ARG TARGETARCH
WORKDIR /app

# The release workflow stages the matching Native AOT archive under amd64/ or arm64/.
COPY --chown=1654:1654 ${TARGETARCH}/ /app/

ENV ASPNETCORE_URLS=http://0.0.0.0:8866 \
    DARKVAULT_DATA=/data

# Keep the data directory writable by the non-root runtime user and empty on first boot.
RUN mkdir /data && chown 1654:1654 /data

VOLUME ["/data"]
EXPOSE 8866
USER 1654:1654
ENTRYPOINT ["/app/DarkVault.Server"]
