# Nombre del compilador
CXX = g++

# Banderas de compilación (Activamos C++17 y que busque los .h de ImGui)
CXXFLAGS = -std=c++17 -Wall -Wformat -I./thirdparty/imgui

# Librerías del sistema requeridas para Gráficos y Captura de Red
LIBS = -lglfw -lGL -lpcap -ldl

# Nombre del ejecutable final
TARGET = packet_sniffer

# Ubicación de los archivos fuente de ImGui
IMGUI_DIR = ./thirdparty/imgui
IMGUI_SOURCES = $(IMGUI_DIR)/imgui.cpp \
                $(IMGUI_DIR)/imgui_draw.cpp \
                $(IMGUI_DIR)/imgui_tables.cpp \
                $(IMGUI_DIR)/imgui_widgets.cpp \
                $(IMGUI_DIR)/imgui_impl_glfw.cpp \
                $(IMGUI_DIR)/imgui_impl_opengl3.cpp

# Los archivos fuente del proyecto
SRC_SOURCES = ./src/main.cpp

# Unión de todas las fuentes y generación de archivos objeto (.o)
SOURCES = $(SRC_SOURCES) $(IMGUI_SOURCES)
OBJECTS = $(SOURCES:.cpp=.o)

# Regla principal por defecto
all: $(TARGET)
	@echo "¡Compilación exitosa! Ejecuta con: ./$(TARGET)"

# Enlace del ejecutable
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

# Compilación de archivos objeto individuales
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Limpieza del proyecto (Borra binarios antiguos)
# make clean
clean:
	rm -f $(OBJECTS) $(TARGET)