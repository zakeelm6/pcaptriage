# pcaptriage + Zeek in one image: no Zeek or Python to install on the host.
#
#   docker run --rm -v "$PWD:/data" ghcr.io/zakeelm6/pcaptriage capture.pcap
#
# Reports land in ./pcaptriage-report next to the capture.
FROM zeek/zeek:lts

# pcaptriage is pure standard library, so no pip step: copy and run.
COPY pcaptriage /opt/pcaptriage/pcaptriage
ENV PYTHONPATH=/opt/pcaptriage \
    PYTHONDONTWRITEBYTECODE=1

LABEL org.opencontainers.image.title="pcaptriage" \
      org.opencontainers.image.description="Automated pcap triage on top of Zeek, MITRE ATT&CK-mapped findings and an HTML report" \
      org.opencontainers.image.source="https://github.com/zakeelm6/pcaptriage" \
      org.opencontainers.image.licenses="MIT"

# Captures and reports live in the mounted directory.
WORKDIR /data
ENTRYPOINT ["python3", "-m", "pcaptriage"]
CMD ["--help"]
