FROM alpine:3.16

WORKDIR /home

RUN apk add --no-cache build-base cmake git \
    && git clone https://github.com/JoshLengel/SeeServ && cd SeeServ \
    && mkdir build && cd build && cmake -G "Unix Makefiles" .. \
    && make -j4 \
    && cd ../example && mkdir logs

EXPOSE 9090

ENTRYPOINT [ "SeeServ/example/bin/SeeServExample", "SeeServ/example/logs/log.txt", "SeeServ/example/pages" ]