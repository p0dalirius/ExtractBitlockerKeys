FROM debian:latest

RUN apt-get -y -q update \
    && apt-get -y -q install nano git wget build-essential librust-gobject-sys-dev libnss3 libnss3-dev

RUN wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc \
    && echo 'export PATH=$PATH:/root/go/bin' >> /root/.bashrc

RUN echo "go clean; go build -v"  >> /root/.bash_history

RUN echo '#!/bin/bash' > /entrypoint.sh \
    && echo 'mkdir -p /workspace/bin/' >> /entrypoint.sh \
    && echo 'cd /workspace/src/' >> /entrypoint.sh \
    && echo '/usr/local/go/bin/go clean' >> /entrypoint.sh \
    && echo 'echo "[+] Building"' >> /entrypoint.sh \
    && echo 'echo " ├──[>] Building for linux i386"' >> /entrypoint.sh \
    && echo 'mkdir -p /workspace/bin/linux/x86/' >> /entrypoint.sh >> /entrypoint.sh \
    && echo 'GOOS=linux GOARCH=386 /usr/local/go/bin/go build -o /workspace/bin/linux/x86/ ExtractBitlockerKeys.go' >> /entrypoint.sh \
    && echo 'echo " ├──[>] Building for linux amd64"' >> /entrypoint.sh \
    && echo 'mkdir -p /workspace/bin/linux/x64/' >> /entrypoint.sh >> /entrypoint.sh \
    && echo 'GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o /workspace/bin/linux/x64/ ExtractBitlockerKeys.go' >> /entrypoint.sh \
    && echo 'echo " ├──[>] Building for Windows i386"' >> /entrypoint.sh \
    && echo 'mkdir -p /workspace/bin/windows/x86/' >> /entrypoint.sh >> /entrypoint.sh \
    && echo 'GOOS=windows GOARCH=386 /usr/local/go/bin/go build -o /workspace/bin/windows/x86/ ExtractBitlockerKeys.go' >> /entrypoint.sh \
    && echo 'echo " └──[>] Building for Windows amd64"' >> /entrypoint.sh \
    && echo 'mkdir -p /workspace/bin/windows/x64/' >> /entrypoint.sh >> /entrypoint.sh \
    && echo 'GOOS=windows GOARCH=amd64 /usr/local/go/bin/go build -o /workspace/bin/windows/x64/ ExtractBitlockerKeys.go' >> /entrypoint.sh \
    && chmod +x /entrypoint.sh

# Prepare workspace volume
RUN mkdir -p /workspace/
VOLUME /workspace/
WORKDIR /workspace/

CMD ["/bin/bash", "/entrypoint.sh"]
