CC = gcc
TARGET = version.dll

all: $(TARGET)

$(TARGET): dllmain.c version.def
	$(CC) -shared -o $(TARGET) dllmain.c version.def -lkernel32

clean:
	rm -f version.dll