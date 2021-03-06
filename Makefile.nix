CFLAGS = -Wall -g3

epd: src/epd.o src/crypto.o src/db.o src/db_util.o src/kmp.o src/key.o src/util.o src/stream.o src/chacha.o src/sha256.o src/ed.o src/curve25519-donna.o
	$(CC) $(CFLAGS) -o build/$@ src/epd.o src/crypto.o src/db.o src/db_util.o src/kmp.o src/key.o src/util.o src/stream.o src/chacha.o src/sha256.o src/ed.o src/curve25519-donna.o
	
test_key: src/test/test_key.o src/stream.o src/crypto.o src/key.o src/sha256.o src/ed.o src/chacha.o src/curve25519-donna.o src/util.o
	$(CC) $(CFLAGS) -o test/$@ src/test/test_key.o src/stream.o src/crypto.o src/key.o src/sha256.o src/ed.o src/chacha.o src/curve25519-donna.o src/util.o
	
test_parser: src/test/test_parser.o
	$(CC) $(CFLAGS) -o test/$@ src/test/test_parser.o

test_db: src/test/test_db.o src/db.o src/db_util.o src/stream.o src/crypto.o src/sha256.o src/chacha.o src/curve25519-donna.o
	$(CC) $(CFLAGS) -o test/$@ src/test/test_db.o src/db.o src/db_util.o src/stream.o src/crypto.o src/sha256.o src/chacha.o src/curve25519-donna.o	

crypto: src/crypto.o src/sha256.o src/chacha.o src/curve25519-donna.o src/ed.o
	$(CC) $(CFLAGS) -o build/$@ src/crypto.o src/sha256.o src/chacha.o src/curve25519-donna.o src/ed.o

src/epd.o: src/epd.c
src/kmp.o: src/kmp.c
src/key.o: src/key.c src/key.h
src/db.o: src/db.c src/db.h
src/db_util.o: src/db_util.c src/db.h
src/crypto.o: src/crypto.c src/crypto.h
src/stream.o: src/stream.c src/stream.h
src/chacha.o: src/chacha.c src/chacha.h
src/sha256.o: src/sha256.c src/sha256.h
src/ed.o: src/ed.c src/ed.h
src/curve25519-donna.o: src/curve25519-donna.c
src/util.o: src/util.c src/util.h

src/test/test_db.o: src/test/test_db.c src/optparse.h
src/test/test_parser.o: src/test/test_parser.c
src/test/test_key.o: src/test/test_key.c

.PHONY:
clean: 
	rm -f src/*.o
	rm -f src/test/*.o
	
.PHONY:
clean_all: clean
	rm -f build/*
	rm -f test/*
