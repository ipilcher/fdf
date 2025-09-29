# ---- Build stage ---- 
FROM alpine:latest AS builder 

# Install build tools and dependencies 
RUN apk add --no-cache \
    build-base \ 
    git \ 
    json-c-dev \
    libmnl-dev 

# --------------------------------- 
# Build libsavl as a static library 
# --------------------------------- 
WORKDIR /deps 
RUN git clone https://github.com/ipilcher/libsavl.git 
WORKDIR /deps/libsavl 
RUN mkdir -p /usr/local/include \
    && gcc -std=gnu99 -O3 -Wall -Wextra -c savl.c -o savl.o \
    && ar rcs libsavl.a savl.o \
    && cp libsavl.a /usr/local/lib/ \
    && cp savl.h /usr/local/include/ 

# --------------------------------- 
# Build fdf 
# --------------------------------- 
WORKDIR /app 
RUN git clone https://github.com/ipilcher/fdf.git . 
WORKDIR /app 

# Link against static libsavl 
RUN gcc -std=gnu99 -O3 -Wall -Wextra \
    -I/usr/local/include -I/usr/include/json-c \
    src/*.c \
    -L/usr/local/lib -lsavl -ljson-c -lmnl \
    -o fdfd


# ---- Runtime stage ---- 
FROM alpine:latest 

# Runtime dependencies 
RUN apk add --no-cache \
    json-c \
    libmnl \
    libstdc++ 

COPY --from=builder /app/fdfd /usr/local/bin/fdfd
ENTRYPOINT ["fdfd"] 
CMD ["--help"]
