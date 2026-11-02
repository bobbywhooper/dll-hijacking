CC = gcc
TARGET = detector.exe

all: $(TARGET)

$(TARGET): main.c
	$(CC) -o $(TARGET) main.c -lpsapi -lwintrust -lkernel32

clean:
	rm -f detector.exe