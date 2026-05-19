# Variables
CXX = g++
CFLAGS = -Wall -std=c++11
LIBS = $(shell pkg-config --cflags --libs allegro-5 allegro_image-5 allegro_font-5 allegro_ttf-5 allegro_primitives-5) -lpcap
TARGET = packetSniffer

# Regla de compilación
all: $(TARGET)

$(TARGET): packetSniffer.cpp
	$(CXX) $(CFLAGS) packetSniffer.cpp -o $(TARGET) $(LIBS)

# Regla para limpiar el ejecutable
clean:
	rm -f $(TARGET)