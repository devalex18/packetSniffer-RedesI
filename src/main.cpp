#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <GLFW/glfw3.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "sniffer.h"

using namespace std;

//Constantes de resolución de la pantalla
#define RESOL_X 1280
#define RESOL_Y 720

int g_selected_packet_idx = -1; 

// Variables de Filtrado
char filter_src_ip[64] = "";
char filter_dst_ip[64] = "";
char filter_src_port[16] = "";
char filter_dst_port[16] = "";
char filter_protocol[32] = "";

// Variable global para controlar la altura dinámica del área de captura de paquetes mediante el Splitter
float g_area1_height = -1.0f; 

// Función auxiliar para evaluar si un paquete cumple con los filtros activos
bool CumpleFiltros(const PacketData& paquete) {
    if (strlen(filter_src_ip) > 0 && paquete.source_ip.find(filter_src_ip) == std::string::npos) return false;
    if (strlen(filter_dst_ip) > 0 && paquete.dest_ip.find(filter_dst_ip) == std::string::npos) return false;
    
    // Búsqueda del protocolo para que sea parcial e ignore mayúsculas/minúsculas
    if (strlen(filter_protocol) > 0 && paquete.protocol.find(filter_protocol) == std::string::npos) return false;
    
    if (strlen(filter_src_port) > 0) {
        std::string p_src = std::to_string(paquete.src_port);
        if (p_src.find(filter_src_port) == std::string::npos) return false;
    }
    if (strlen(filter_dst_port) > 0) {
        std::string p_dst = std::to_string(paquete.dst_port);
        if (p_dst.find(filter_dst_port) == std::string::npos) return false;
    }
    
    return true;
}

// Exportación a CSV
void exportar_csv() {
    // Exclusión mutua, bloqueo a los paquetes para empezar a guardar y que no hayan paquetes a medias
    lock_guard<std::mutex> lock(g_packets_mutex);
    if (g_packets.empty()) return;

    // Nombre del archivo .csv
    // Podríamos cambiarlo a que el usuario ingrese el nombre que quiera
    ofstream archivo("reporte_sniffer.csv");
    if (!archivo.is_open()) return;

    // Cabecera del archivo csv
    archivo << "No.\tTiempo\tOrigen\tDestino\tProtocolo\tLongitud\tInformacion\n";
    int exportados = 0;
    
    for (const auto& pkt : g_packets) {
        // Solo escribe en el CSV si el paquete pasa los filtros establecidos
        if (CumpleFiltros(pkt)) {
            archivo << pkt.id << "\t"
                    << pkt.timestamp << "\t"
                    << pkt.source_ip << "\t"
                    << pkt.dest_ip << "\t"
                    << pkt.protocol << "\t"
                    << pkt.length << "\t"
                    << "\"" << pkt.info << "\"\n";
            exportados++;
        }
    }
    archivo.close();
    
    // Salida a terminal
    cout << "Reporte exportado exitosamente con " << exportados << " paquetes a 'reporte_sniffer.csv'" << endl;
}

// Dibujado 
void dibujar_hexdump(const std::vector<uint8_t>& bytes) {
    ImGui::BeginChild("HexdumpView", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    
    for (size_t i = 0; i < bytes.size(); i += 16) {
        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "%04X  ", (unsigned int)i);
        ImGui::SameLine();

        stringstream hex_stream;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < bytes.size()) {
                hex_stream << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i + j] << " ";
            } else {
                hex_stream << "   ";
            }
            if (j == 7) hex_stream << " ";
        }
        ImGui::Text("%s", hex_stream.str().c_str());
        ImGui::SameLine();
        ImGui::Text(" | ");
        ImGui::SameLine();

        std::string ascii_str = "";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < bytes.size()) {
                uint8_t ch = bytes[i + j];
                if (ch >= 32 && ch <= 126) ascii_str += (char)ch;
                else ascii_str += ".";
            }
        }
        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "%s", ascii_str.c_str());
    }
    ImGui::EndChild();
}

int main(int, char**) {
    //Inicializa el ImGUI
    if (!glfwInit()) return 1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    // Crear la ventana con ImGUI
    GLFWwindow* window = glfwCreateWindow(RESOL_X, RESOL_Y, "Packet Sniffeador", nullptr, nullptr);
    if (!window) return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");
    ImGui::StyleColorsDark();

    // Obtener las interfaces de red y guardarlas en el vector de strings
    vector<std::string> interfaces = ObtenerInterfacesRed();
    int interfaz_seleccionada_idx = 0;

    while (!glfwWindowShouldClose(window)) {
        int ancho_ventana, alto_ventana;

        //Obtiene eventos de GLFW y genera un nuevo frame
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        glfwGetFramebufferSize(window, &ancho_ventana, &alto_ventana);
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2((float)ancho_ventana, (float)alto_ventana));

        ImGui::Begin("Consola Sniffer", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

        ImGui::TextColored(ImVec4(1, 1, 0, 1), "SELECCIÓN DE HARDWARE Y OPERACIÓN");
        
        std::string combo_preview = interfaces.empty() ? "No se encontraron interfaces" : interfaces[interfaz_seleccionada_idx];
        ImGui::PushItemWidth(250);

        // Mostrar las interfaces de red a capturar (enp0s3 y otros)
        if (ImGui::BeginCombo("Tarjeta de Red", combo_preview.c_str())) {
            for (int n = 0; n < (int)interfaces.size(); n++) {
                const bool is_selected = (interfaz_seleccionada_idx == n);
                if (ImGui::Selectable(interfaces[n].c_str(), is_selected))
                    interfaz_seleccionada_idx = n;
                if (is_selected)
                    ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
        ImGui::PopItemWidth();
        
        //Botones para la captura de paquetes. Pausa y despausa
        ImGui::SameLine();
        if (!g_is_capturing) {
            if (ImGui::Button("Iniciar Captura", ImVec2(130, 25)) && !interfaces.empty()) {
                IniciarHiloCaptura(interfaces[interfaz_seleccionada_idx]);
            }
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.1f, 0.1f, 1.0f));
            if (ImGui::Button("Detener Captura", ImVec2(130, 25))) {
                DetenerCaptura();
            }
            ImGui::PopStyleColor();
        }
        
        //En la misma línea; botones para exportar y limpiar la captura actual
        ImGui::SameLine();
        if (ImGui::Button("Exportar CSV", ImVec2(110, 25))) {
            exportar_csv();
        }
        ImGui::SameLine();
        if (ImGui::Button("Limpiar Todo", ImVec2(110, 25))) {
            std::lock_guard<std::mutex> lock(g_packets_mutex);
            g_packets.clear();
            g_selected_packet_idx = -1;
            g_packet_id_counter = 1;
        }

        // Sección para mostrar los filtros, compara mediante el string
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.3f, 0.8f, 1.0f, 1.0f), "Filtros");
        
        // Información separada sobre el paquete capturado
        ImGui::PushItemWidth(120); // Reducimos el ancho un poco para que quepan los 5 filtros
        ImGui::InputText("IP Orig", filter_src_ip, IM_ARRAYSIZE(filter_src_ip));
        ImGui::SameLine();
        ImGui::InputText("IP Dest", filter_dst_ip, IM_ARRAYSIZE(filter_dst_ip));
        ImGui::SameLine();
        ImGui::InputText("Pto Orig", filter_src_port, IM_ARRAYSIZE(filter_src_port));
        ImGui::SameLine();
        ImGui::InputText("Pto Dest", filter_dst_port, IM_ARRAYSIZE(filter_dst_port));
        ImGui::SameLine();
        ImGui::InputText("Proto", filter_protocol, IM_ARRAYSIZE(filter_protocol));
        ImGui::PopItemWidth();

        ImGui::Separator();

        // ÁREA 1: REGISTRO DE TRÁFICO
        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "Registro de Tráfico");
        
        // Inicialización de la altura si es el primer renderizado
        if (g_area1_height < 0) {
            g_area1_height = alto_ventana * 0.35f;
        }

        // Variable local para rastrear si el usuario estaba al fondo antes de procesar las filas
        bool estaba_al_fondo = false;

        // Columnas con los datos filtrados del paquete capturado
        if (ImGui::BeginTable("Trafico de la Red", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, g_area1_height))) {
            ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupColumn("Tiempo", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("IP Origen", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("IP Destino", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("Protocolo", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Longitud", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Informacion", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            // Verificar la posición del scroll vertical antes de iterar
            float scroll_y = ImGui::GetScrollY();
            float max_scroll_y = ImGui::GetScrollMaxY();

            // Si el scroll está al final o muy cerca de él (5px), activar autoscroll
            if(scroll_y >= max_scroll_y - 5.0f){
                estaba_al_fondo = true;
            }

            // Exclusión mutua para leer los paquetes capturados de forma segura
            g_packets_mutex.lock();
            for (size_t i = 0; i < g_packets.size(); ++i) {
                const PacketData& paquete = g_packets[i];

                if (!CumpleFiltros(paquete)) continue;

                // Configuración de colores base (U32) para las celdas permanentes
                // (Basado en el estilo por protocolo de Wireshark)
                ImU32 bg_color = ImGui::GetColorU32(ImVec4(0.12f, 0.12f, 0.12f, 1.0f)); // Fondo oscuro por defecto
                ImVec4 text_color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);                    // Texto blanco por defecto

                if (paquete.protocol == "TCP") {
                    bg_color = ImGui::GetColorU32(ImVec4(0.22f, 0.15f, 0.32f, 1.0f)); // Morado
                } 
                else if (paquete.protocol == "UDP") {
                    bg_color = ImGui::GetColorU32(ImVec4(0.15f, 0.25f, 0.35f, 1.0f)); // Azul
                } 
                else if (paquete.protocol == "ICMP") {
                    bg_color = ImGui::GetColorU32(ImVec4(0.12f, 0.32f, 0.18f, 1.0f)); // Verde
                }
                else if (paquete.protocol == "ARP") {
                    bg_color = ImGui::GetColorU32(ImVec4(0.40f, 0.38f, 0.26f, 1.0f)); // Beige
                    text_color = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);                     // Texto negro para contraste
                }
                else if (paquete.protocol == "ICMPv6" || paquete.protocol == "IPv6") {
                    bg_color = ImGui::GetColorU32(ImVec4(0.40f, 0.28f, 0.40f, 1.0f)); // Lila
                }

                // Si esta fila específica es la seleccionada por el usuario, sobreescribimos con el color de selección azul de ImGUI
                bool is_selected = (g_selected_packet_idx == (int)i);
                if (is_selected) {
                    bg_color = ImGui::GetColorU32(ImGuiCol_HeaderActive);
                    text_color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                }

                ImGui::TableNextRow();

                // Dibujar celdas poniendo el color de fondo persistente y el texto correspondiente
                for (int col = 0; col < 7; ++col) {
                    ImGui::TableSetColumnIndex(col);
                    // Esto pinta el fondo completo de la celda de forma permanente sin importar el ratón
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_CellBg, bg_color);

                    ImGui::PushStyleColor(ImGuiCol_Text, text_color);
                    
                    if (col == 0) {
                        char label[32]; sprintf(label, "%d", paquete.id);
                        // El Selectable se mantiene transparente para que no altere los colores manuales de celda
                        ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0,0,0,0));
                        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(1.0f, 1.0f, 1.0f, 0.15f)); // Sutil brillo al pasar el mouse
                        
                        if (ImGui::Selectable(label, is_selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                            g_selected_packet_idx = (int)i;
                        }
                        ImGui::PopStyleColor(2);
                    }
                    else if (col == 1) ImGui::Text("%s", paquete.timestamp.c_str());
                    else if (col == 2) ImGui::Text("%s", paquete.source_ip.c_str());
                    else if (col == 3) ImGui::Text("%s", paquete.dest_ip.c_str());
                    else if (col == 4) ImGui::Text("%s", paquete.protocol.c_str());
                    else if (col == 5) ImGui::Text("%d", paquete.length);
                    else if (col == 6) ImGui::Text("%s", paquete.info.c_str());

                    ImGui::PopStyleColor(); // Quita text_color
                }
            }
            g_packets_mutex.unlock();
            
            // Ejecución del autoscroll
            // Si el programa está capturando y el usuario no ha subido manualmente, se forza la vista al fondo
            if (g_is_capturing && estaba_al_fondo) {
                ImGui::SetScrollHereY(1.0f);
            }

            ImGui::EndTable();
        }

        // ----- SPLITTER ENTRE ÁREA 1 y LAS ÁREAS 2 Y 3 -----
        // Cambia dinámicamente el puntero a una barra de redimensionamiento vertical al pasar el mouse
        ImGui::Button("##SplitterHorizontal", ImVec2(-1, 6.0f));
        if (ImGui::IsItemActive()) {
            g_area1_height += ImGui::GetIO().MouseDelta.y;
            // Limitadores para evitar que colapse la interfaz por completo hacia arriba o abajo
            if (g_area1_height < 60.0f) g_area1_height = 60.0f;
            if (g_area1_height > alto_ventana * 0.70f) g_area1_height = alto_ventana * 0.70f;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
        }

        ImGui::Separator();

        //Pánel inferior - Recalcula el tamaño restante de la pantalla tras el movimiento del Splitter
        float lower_height = alto_ventana - g_area1_height - 190.0f; 
        if (lower_height < 100.0f) lower_height = 100.0f; // Salvaguarda de espacio mínimo

        ImGui::Columns(2, "LowerPanels", true);

        /*----- Datos por capas -----*/
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "Análisis por Capas (Modelo OSI/TCP-IP)");
        ImGui::BeginChild("TreePanel", ImVec2(0, lower_height), true);
        
        //Exclusión para el paquete seleccionado
        g_packets_mutex.lock();
        // Información en el área 2
        if (g_selected_packet_idx != -1 && g_selected_packet_idx < (int)g_packets.size()) {
            const PacketData& paquete = g_packets[g_selected_packet_idx];

            if (ImGui::TreeNode("Capa II: Enlace de Datos")) {
                ImGui::Text("MAC Origen: %s", paquete.mac_src.c_str());
                ImGui::Text("MAC Destino: %s", paquete.mac_dst.c_str());
                ImGui::Text("Type del Frame: 0x%04X", paquete.eth_type);
                ImGui::TreePop();
            }
            if (paquete.eth_type == ETHERTYPE_IP && ImGui::TreeNode("Capa III: Red con IPv4")) {
                ImGui::Text("IP Origen: %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino: %s", paquete.dest_ip.c_str());
                ImGui::Text("TTL (Tiempo de vida): %d", paquete.ip_ttl);
                ImGui::Text("Protocolo interno codificado: %d", paquete.ip_proto);
                ImGui::TreePop();
            }
            string trans_lbl = "Capa IV: Transporte " + paquete.protocol;
            if ((paquete.protocol == "TCP" || paquete.protocol == "UDP") && ImGui::TreeNode(trans_lbl.c_str())) {
                ImGui::Text("Puerto Origen: %d", paquete.src_port);
                ImGui::Text("Puerto Destino: %d", paquete.dst_port);
                ImGui::TreePop();
            }
        }
        else {
            ImGui::Text("Selecciona un paquete para examinar sus cabeceras.");
        }
        g_packets_mutex.unlock();
        //Fin exclusión mutua

        ImGui::EndChild();

        ImGui::NextColumn();

        /*----- Datos Hexadecimales -----*/
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 1.0f, 1.0f), "Volcado de Bytes Reales");
        ImGui::BeginChild("HexPanel", ImVec2(0, lower_height), true);
        
        //Otra exclusión mutua, no vaya a ser
        g_packets_mutex.lock();
        if (g_selected_packet_idx != -1 && g_selected_packet_idx < (int)g_packets.size()) {
            dibujar_hexdump(g_packets[g_selected_packet_idx].raw_bytes);
        } else {
            ImGui::Text("Selecciona un paquete para ver su contenido en hexadecimal");
        }
        g_packets_mutex.unlock();
        //Fin
        
        ImGui::EndChild();
        ImGui::Columns(1);
        ImGui::End();

        //Dibujar a pantalla
        ImGui::Render();
        glViewport(0, 0, ancho_ventana, alto_ventana);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    //Apaga el hilo secundario de red si la ventana se cierra abruptamente
    DetenerCaptura(); 
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}