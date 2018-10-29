all: fuzz fuzz_v2

fuzz: fuzz.c
	$(CC) $(CFLAGS) -c fuzz.c -I ../../src/liblzma/api/
	$(CXX) $(CXXFLAGS) -lFuzzingEngine fuzz.o -o $(OUT)/fuzz \
	      ../../src/liblzma/.libs/liblzma.a
	
fuzz_v2: fuzz_v2.c
	$(CC) $(CFLAGS) -c fuzz_v2.c -I ../../src/liblzma/api/
	$(CXX) $(CXXFLAGS) -lFuzzingEngine fuzz.o -o $(OUT)/fuzz_v2 \
	      ../../src/liblzma/.libs/liblzma.a

clean:
	rm -f *.o
