BUILD_DIR = ./build
HEADER_DIR = ./header
SOURCE_DIR = ./source

all: firewall

firewall: packet.o main.o
	g++ -g -o ${BUILD_DIR}/firewall ${BUILD_DIR}/packet.o ${BUILD_DIR}/main.o -lnetfilter_queue

main.o: makeBuildFolder
	g++ -g -c -o ${BUILD_DIR}/main.o ${SOURCE_DIR}/main.cpp

makeBuildFolder:
	mkdir -p ${BUILD_DIR}

packet.o:
	g++ -g -c -o ${BUILD_DIR}/packet.o ${SOURCE_DIR}/packet.cpp

clean:
	rm -f ${BUILD_DIR}/*
