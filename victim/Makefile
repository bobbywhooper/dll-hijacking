CC = gcc
TARGET = victim.exe

all: $(TARGET)

$(TARGET): main.c
	$(CC) -o $(TARGET) main.c -lversion

clean:
	rm -f victim.exe