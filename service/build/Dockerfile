# Build Context: service/build/server

# $ cd go-nvd
# $ GOOS=linux go build -o service/build/bin/ ./...
# $ cd service/build
# $ docker build -t nvd-tools .

FROM alpine:3.17

EXPOSE 8080
EXPOSE 6060

COPY ./bin /nvd/bin

ENV PATH="${PATH}:/nvd/bin"

ENTRYPOINT ["server"]
