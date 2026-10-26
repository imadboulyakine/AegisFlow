# Test cases for dockerfile-unverified-remote-content (run: make sast-test).
FROM alpine:3.22@sha256:0000000000000000000000000000000000000000000000000000000000000000

# ok: dockerfile-unverified-remote-content
ADD --checksum=sha256:1111111111111111111111111111111111111111111111111111111111111111 https://example.invalid/tool.tar.gz /tmp/tool.tar.gz

# ok: dockerfile-unverified-remote-content
ADD rootfs.tar /

# ruleid: dockerfile-unverified-remote-content
ADD https://example.invalid/tool.tar.gz /tmp/tool.tar.gz

# ok: dockerfile-unverified-remote-content
RUN curl -fsSLo /tmp/tool.tgz https://example.invalid/tool.tgz && echo "abc  /tmp/tool.tgz" | sha256sum -c -

# ruleid: dockerfile-unverified-remote-content
RUN curl -fsSL https://example.invalid/install.sh | sh

# ruleid: dockerfile-unverified-remote-content
RUN wget -qO- https://example.invalid/install.sh | sudo bash -s -- --yes

# ruleid: dockerfile-unverified-remote-content
RUN apk add --no-cache ca-certificates && curl -fsSL https://example.invalid/i.sh | /bin/bash
