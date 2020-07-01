# build on ubuntu 20.04, with gcc 9.3.0 

CFLAGS :=  -g -O0 -Wall --no-builtin-printf --no-inline -fcf-protection=none  
PROGRAM_NAME:=simple_echoserver

all: $(PROGRAM_NAME)

$(PROGRAM_NAME): $(PROGRAM_NAME).c
	gcc $(CFLAGS) -o $@ $^

clean:
	rm -f $(PROGRAM_NAME)

