all: urlextractor

urlextractor: urlextractor.o http_parser.o picohttpparser.o
	gcc -g -o urlextractor urlextractor.o http_parser.o picohttpparser.o -lpcap

urlextractor.o: urlextractor.c http_parser.h
	gcc -g -c urlextractor.c

http_parser.o: http_parser.c http_parser.h
	gcc -g -c http_parser.c

picohttpparser.o:  picohttpparser.c picohttpparser.h
	gcc -g -c picohttpparser.c

clean:
	rm -rf urlextractor *.o
