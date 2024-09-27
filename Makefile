CC=gcc
CFLAGS= -Wall -pedantic -std=c99 -Wextra -Wmissing-prototypes 
OPTIMIZE=-O3

TARGET=sigmaker

all: $(TARGET)

debug: CFLAGS += -g 
debug: OPTIMIZE = -O0
debug: $(TARGET)

$(TARGET) : sigmaker.c 
	$(CC) $(CFLAGS) $(OPTIMIZE) $^ -o $@


.PHONY : clean
clean :
	rm -f $(TARGET)

