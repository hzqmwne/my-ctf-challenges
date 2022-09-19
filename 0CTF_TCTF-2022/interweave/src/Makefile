CC := gcc
CFLAGS := -Wall -Wextra -g -O2 -flto 
# LDFLAGS :=

TARGET := interweave
TARGET_DEBUG := $(TARGET)_with_debuginfo

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(TARGET_DEBUG): $(patsubst %.c, %.o, $(wildcard *.c))
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TARGET): $(TARGET_DEBUG)
	strip -o $@ $^

.PHONY: clean
clean:
	rm -f $(TARGET) $(TARGET_DEBUG) *.o
