# Container image of trustbeat-signature: ghcr.io/trustbeat/trustbeat-signature.
#
# Not a Go build. The image packs the binary from the release archives — the bytes listed in the
# release's cosign-signed SHA256SUMS — so the container runs exactly what was released. The build
# context is prepared by .github/workflows/docker.yml: linux-amd64/ and linux-arm64/, each holding
# one archive's contents.
#
# distroless/static:nonroot = CA certificates (for `preserve` over HTTPS), no shell, uid 65532.
# Pinned by digest; bump it deliberately.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETARCH
ARG VERSION

LABEL org.opencontainers.image.title="trustbeat-signature" \
      org.opencontainers.image.description="Extract electronic signatures for long-term preservation — the signed file stays local" \
      org.opencontainers.image.source="https://github.com/TrustBeat/trustbeat-signature" \
      org.opencontainers.image.url="https://trustbeat.eu/en" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

COPY linux-${TARGETARCH}/trustbeat-signature /usr/local/bin/trustbeat-signature
COPY linux-${TARGETARCH}/LICENSE linux-${TARGETARCH}/THIRD_PARTY_LICENSES.txt /usr/share/doc/trustbeat-signature/

# Mount the directory holding the signed file here: docker run -v "$PWD:/work" …
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/trustbeat-signature"]
