# Define the compiler
CC=arm-none-eabi-gcc
# Define the compiler flags
CFLAGS=-mthumb -mcpu=cortex-m4 -mfloat-abi=soft -specs=nosys.specs -Os

# The target file to be compiled
TARGET=firmware

# The object files to be compiled
OBJS=$(TARGET).o aes.o

all: $(TARGET)

# Rule to compile the source files
$(TARGET).o: $(TARGET).c aes.h
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to link the object files
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^


aes.o: aes.c aes.h
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	rm -f $(TARGET) $(OBJS)