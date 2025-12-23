CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused-result -Wno-unused-function -O3 -flto -finline-functions -fomit-frame-pointer -fno-stack-protector -fno-pie -no-pie -DNDEBUG
LDFLAGS = -flto -no-pie
LEX = flex
YACC = bison
STRIP = strip
TARGET_DEBUG = pwn_with_debuginfo
TARGET = pwn

OBJS = main.o bigint.o parser1_support.o parser1.tab.o lex.yy1.o parser2.tab.o lex.yy2.o

all: $(TARGET) $(TARGET_DEBUG)

parser1.tab.c parser1.tab.h: parser1.y
	$(YACC) -d -Wall -v -o parser1.tab.c parser1.y

lex.yy1.c lex.yy1.h: parser1.l parser1.tab.h
	$(LEX) --header-file=lex.yy1.h -o lex.yy1.c parser1.l

parser1.tab.o: lex.yy1.h

parser2.tab.c parser2.tab.h: parser2.y
	$(YACC) -d -Wall -v -o parser2.tab.c parser2.y

lex.yy2.c lex.yy2.h: parser2.l parser2.tab.h
	$(LEX) --header-file=lex.yy2.h -o lex.yy2.c parser2.l

parser2.tab.o: lex.yy2.h

$(TARGET_DEBUG): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) -lfl

$(TARGET): $(TARGET_DEBUG)
	$(STRIP) -o $(TARGET) $(TARGET_DEBUG)

clean:
	rm -f $(TARGET) $(TARGET_DEBUG) $(OBJS) parser1.tab.c parser1.tab.h parser1.output lex.yy1.c lex.yy1.h parser2.tab.c parser2.tab.h parser2.output lex.yy2.c lex.yy2.h

.PHONY: all clean
