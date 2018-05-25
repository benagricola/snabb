FROM raptorjit AS build
COPY . /snabb
#RUN cd snabb && make -j
RUN cd snabb/src && make -j

FROM raptorjit
RUN apk add --no-cache libgcc
COPY --from=build /snabb/src/snabb /usr/local/bin/

VOLUME /u
WORKDIR /u

ENTRYPOINT ["/usr/local/bin/snabb"]