CFLAGS = -g -Wall -fPIC -fvisibility=hidden
CXXFLAGS = $(CFLAGS) -std=c++11

TARGETS = libsmartcard.so

.PHONY: all clean pkg cleanpkg

all: $(TARGETS)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@


aes_whitebox_compiler: aes_whitebox_compiler.o
	$(CXX) $^ -o $@ -lntl

aes_whitebox_tables.cc: aes_whitebox_compiler
	./aes_whitebox_compiler aes128 7e28a99358f40673cdb160f3ed02ebe2 5dc00f4ecde50a22a5166e6d573f1f03 19dcb026b0f57882e31dff9e85b437ff

aes_whitebox.o: aes_whitebox.cc aes_whitebox_tables.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@


libsmartcard_with_debuginfo.so: libsmartcard.o aes_whitebox.o md5c.o
	$(CC) -shared $^ -o $@

libsmartcard.so: libsmartcard_with_debuginfo.so
	strip -o $@ $^ 

clean:
	rm -f *.o aes_whitebox_compiler aes_whitebox_tables.cc libsmartcard_with_debuginfo.so $(TARGETS)


pkg: dist/client

dist/client: client.py libsmartcard.so
	pyinstaller -F $<

cleanpkg:
	rm -rf dist/ build/ client.spec

