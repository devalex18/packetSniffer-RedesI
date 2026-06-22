#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
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

// Tipo de acción pendiente que lanzó la confirmación, NINGUNA = no hay modal abierto
enum class AccionPendiente { NINGUNA, CAMBIAR_INTERFAZ, LIMPIAR, SALIR };
AccionPendiente g_accion_pendiente = AccionPendiente::NINGUNA;
int g_interfaz_destino_idx = -1;          // Índice de la interfaz a la que se quiere cambiar (caso CAMBIAR_INTERFAZ)
bool g_solicitud_cierre_ventana = false;  // true cuando GLFW pidió cerrar y estamos confirmando con el usuario
bool g_abrir_popup_confirmacion = false;  // Bandera para abrir el popup en el siguiente frame y evitar erroes por capas (ImGUI)

// Variables de Filtrado
char filter_src_ip[64] = "";
char filter_dst_ip[64] = "";
char filter_src_port[16] = "";
char filter_dst_port[16] = "";
char filter_protocol[32] = "";
char filter_payload[128] = "";
bool g_show_dpi_search = false;

// Variable global para controlar la altura dinámica del área de captura de paquetes mediante el Splitter
float g_area1_height = -1.0f; 

// Zoom global aplicado a las Áreas 1, 2 y 3 (tabla de tráfico, capas OSI, hexdump)
float g_zoom_nivel = 1.0f;
const float ZOOM_MIN  = 0.70f;
const float ZOOM_MAX  = 2.00f;
const float ZOOM_PASO = 0.10f;

// Activa/desactiva el coloreado por protocolo en el Área 1
bool g_color_protocolo_activo = true;
int  g_text_color_idx_previo  = 0;   // Guarda el color de letra antes de desactivar colores

// Tono de los colores pastel de fondo: 0=Claro 1=Medio 2=Oscuro, MODIFICAR
int g_table_bg_tone_idx = 0;
const char* g_tone_names[3] = { "Claro", "Medio", "Oscuro" };

// Color del texto de las celdas: 0=Negro 1=Gris oscuro 2=Blanco
int g_table_text_color_idx = 0;
const char* g_text_color_names[3] = { "Negro", "Gris", "Blanco" };
const ImVec4 g_text_color_options[3] = {
    ImVec4(0.0f, 0.0f, 0.0f, 1.0f),    // Negro
    ImVec4(0.20f, 0.20f, 0.20f, 1.0f), // Gris oscuro
    ImVec4(1.0f, 1.0f, 1.0f, 1.0f)     // Blanco
};

// Aplicar el tono seleccionado a un color pastel (multiplica hacia abajo para oscurecer)
ImVec4 AplicarTono(const ImVec4& base_claro) {
    if (g_table_bg_tone_idx == 0) return base_claro; // Claro (original)
    float factor = (g_table_bg_tone_idx == 1) ? 0.80f : 0.55f; // Medio / Oscuro
    return ImVec4(base_claro.x * factor, base_claro.y * factor, base_claro.z * factor, base_claro.w);
}

// Paleta fija de 10 colores pastel seleccionables
const int NUM_PALETA = 10;
const char* g_paleta_nombres[NUM_PALETA] = {
    "Lavanda", "Azul cielo", "Verde menta", "Amarillo", "Lila",
    "Durazno", "Rosa salmon", "Lima", "Turquesa", "Gris"
};
const ImVec4 g_paleta_colores[NUM_PALETA] = {
    ImVec4(0.78f, 0.70f, 0.95f, 1.0f), // Lavanda
    ImVec4(0.68f, 0.85f, 0.95f, 1.0f), // Azul cielo
    ImVec4(0.72f, 0.95f, 0.75f, 1.0f), // Verde menta
    ImVec4(0.98f, 0.95f, 0.70f, 1.0f), // Amarillo
    ImVec4(0.88f, 0.75f, 0.95f, 1.0f), // Lila
    ImVec4(0.95f, 0.82f, 0.68f, 1.0f), // Durazno
    ImVec4(0.98f, 0.72f, 0.72f, 1.0f), // Rosa salmon
    ImVec4(0.88f, 0.92f, 0.70f, 1.0f), // Lima
    ImVec4(0.70f, 0.95f, 0.90f, 1.0f), // Turquesa
    ImVec4(0.85f, 0.85f, 0.85f, 1.0f)  // Gris
};

// Lista de protocolos configurables y su índice de color asignado en la paleta (por defecto)
struct ProtocoloColor { const char* nombre; int paleta_idx; };
ProtocoloColor g_protocolo_colores[] = {
    { "TCP",    0 }, // Lavanda
    { "UDP",    1 }, // Azul cielo
    { "ICMP",   2 }, // Verde menta
    { "ARP",    3 }, // Amarillo
    { "IPv6",   4 }, // Lila
    { "ICMPv6", 4 }, // Lila
    { "IGMP",   2 }, // Verde menta
    { "OSPF",   5 }, // Durazno
    { "GRE",    1 }, // Azul cielo
    { "ESP",    6 }, // Rosa salmon
    { "AH",     6 }, // Rosa salmon
    { "SCTP",   7 }, // Lima
    { "EIGRP",  5 }, // Durazno
    { "PIM",    8 }, // Turquesa
    { "VRRP",   9 }, // Gris
    { "L2TP",   4 }, // Lila
    { "RSVP",   2 }, // Verde menta
    { "IPIP",   1 }, // Azul cielo
    // Protocolos detectados por puerto
    { "SSH",        0 }, // Lavanda
    { "Telnet",     6 }, // Rosa salmon
    { "RDP",        4 }, // Lila
    { "VNC",        4 }, // Lila
    { "HTTP",       1 }, // Azul cielo
    { "HTTPS",      2 }, // Verde menta
    { "HTTP-Alt",   1 }, // Azul cielo
    { "HTTPS-Alt",  2 }, // Verde menta
    { "SMTP",       5 }, // Durazno
    { "SMTPS",      5 }, // Durazno
    { "SMTP-Sub",   5 }, // Durazno
    { "POP3",       5 }, // Durazno
    { "POP3S",      5 }, // Durazno
    { "IMAP",       5 }, // Durazno
    { "IMAPS",      5 }, // Durazno
    { "DNS",        3 }, // Amarillo
    { "mDNS",       3 }, // Amarillo
    { "NetBIOS-NS", 9 }, // Gris
    { "NetBIOS-DG", 9 }, // Gris
    { "NetBIOS-SS", 9 }, // Gris
    { "SMB",        9 }, // Gris
    { "FTP",        8 }, // Turquesa
    { "FTP-Data",   8 }, // Turquesa
    { "TFTP",       8 }, // Turquesa
    { "FTPS",       8 }, // Turquesa
    { "FTPS-Data",  8 }, // Turquesa
    { "SNMP",       7 }, // Lima
    { "SNMP-Trap",  7 }, // Lima
    { "Syslog",     7 }, // Lima
    { "NTP",        3 }, // Amarillo
    { "DHCP-Srv",   3 }, // Amarillo
    { "DHCP-Cli",   3 }, // Amarillo
    { "DHCPv6-Cli", 3 }, // Amarillo
    { "DHCPv6-Srv", 3 }, // Amarillo
    { "MySQL",      6 }, // Rosa salmon
    { "PostgreSQL", 6 }, // Rosa salmon
    { "MSSQL",      6 }, // Rosa salmon
    { "Oracle",     6 }, // Rosa salmon
    { "Redis",      6 }, // Rosa salmon
    { "MongoDB",    6 }, // Rosa salmon
    { "SIP",        4 }, // Lila
    { "SIPS",       4 }, // Lila
    { "OpenVPN",    2 }, // Verde menta
    { "IKE",        2 }, // Verde menta
    { "IPSec-NAT",  2 }, // Verde menta
    { "BGP",        0 }, // Lavanda
    { "LDAP",       7 }, // Lima
    { "LDAPS",      7 }, // Lima
    { "Kerberos",   0 }, // Lavanda
    { "RPC",        9 }, // Gris
    { "NFS",        8 }, // Turquesa
    { "BitTorrent", 6 }, // Rosa salmon
};
const int NUM_PROTOCOLOS_CONFIG = sizeof(g_protocolo_colores) / sizeof(ProtocoloColor);

// Devuelve el color
ImVec4 ColorParaProtocolo(const std::string& protocolo) {
    if (!g_color_protocolo_activo)
        return ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    for (int i = 0; i < NUM_PROTOCOLOS_CONFIG; ++i) {
        if (protocolo == g_protocolo_colores[i].nombre) {
            return g_paleta_colores[g_protocolo_colores[i].paleta_idx];
        }
    }
    return ImVec4(0.88f, 0.88f, 0.88f, 1.0f);
}

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
    if (strlen(filter_payload) > 0) {
        // Convertir el vector de bytes puros a un string
        std::string payload_str(paquete.raw_bytes.begin(), paquete.raw_bytes.end());
        std::string busqueda_str = filter_payload;
        
        // Convertir ambos textos a minúsculas para la búsqueda
        std::transform(payload_str.begin(), payload_str.end(), payload_str.begin(), ::tolower);
        std::transform(busqueda_str.begin(), busqueda_str.end(), busqueda_str.begin(), ::tolower);

        // Si la palabra no se encuentra en ningún byte del paquete, ocultar
        if (payload_str.find(busqueda_str) == std::string::npos) {
            return false;
        }
    }
    
    return true;
}

// Exportación a CSV
void exportar_csv() {
    // Exclusión mutua, bloqueo a los paquetes para empezar a guardar y que no hayan paquetes a medias
    lock_guard<std::mutex> lock(g_packets_mutex);
    if (g_packets.empty()) return;

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
}

// Dibujado del área 3
void dibujar_hexdump(const std::vector<uint8_t>& bytes) {
    // Crear subventana interna para esta área con scrollbar horizontal
    ImGui::BeginChild("HexdumpView", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::SetWindowFontScale(g_zoom_nivel);
    
    // Agrupación en bloques de 16 Bytes
    for (size_t i = 0; i < bytes.size(); i += 16) {
        // Offset, imprimir indice de memoria donde arranca la fila actual
        ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "%04X  ", (unsigned int)i);
        ImGui::SameLine();

        // Recorrer los 16 Bytes correspondientes a la fila
        stringstream hex_stream;
        for (size_t j = 0; j < 16; ++j) {
            // Si existe el byte se agrega al flujo de texto hex_stream
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

        // Volver a iterar en los 16 Bytes para extraer su equivalencia en caracteres alfabeticos
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

// Ejecutar la acción que el modal de confirmación tenga pendiente
void EjecutarAccionPendiente(int& interfaz_seleccionada_idx, bool& debe_cerrar_app) {
    switch (g_accion_pendiente) {
        case AccionPendiente::CAMBIAR_INTERFAZ: {
            if (g_is_capturing) DetenerCaptura();
            std::lock_guard<std::mutex> lock(g_packets_mutex);
            g_packets.clear();
            g_selected_packet_idx = -1;
            g_packet_id_counter = 1;
            g_capture_start_time = { -1, 0 };
            interfaz_seleccionada_idx = g_interfaz_destino_idx;
            break;
        }
        case AccionPendiente::LIMPIAR: {
            std::lock_guard<std::mutex> lock(g_packets_mutex);
            g_packets.clear();
            g_selected_packet_idx = -1;
            g_packet_id_counter = 1;
            g_capture_start_time = { -1, 0 };
            break;
        }
        case AccionPendiente::SALIR:
            debe_cerrar_app = true;
            break;
        default:
            break;
    }

    g_accion_pendiente = AccionPendiente::NINGUNA;
    g_interfaz_destino_idx = -1;
    ImGui::CloseCurrentPopup();
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

    // Iniciar ImGUI para usarlo con una configuración de colores oscuros
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");
    ImGui::StyleColorsDark();

    // Obtener las interfaces de red y guardarlas en el vector de strings
    vector<std::string> interfaces = ObtenerInterfacesRed();
    int interfaz_seleccionada_idx = 0;

    // Bucle de la ventana
    bool debe_cerrar_app = false; // Controla la salida real del bucle (separado del flag nativo de GLFW)
    while (!debe_cerrar_app) {
        int ancho_ventana, alto_ventana;

        //Obtiene eventos de GLFW y genera un nuevo frame
        glfwPollEvents();

        // Si el usuario pide cerrar (botón X / alt+F4) se intercepta y cancela el cierre nativo, si hay
        // datos sin guardar o captura activa muetsra el modal de confirmación
        if (glfwWindowShouldClose(window)) {
            glfwSetWindowShouldClose(window, GLFW_FALSE); // Cancela el cierre automático de GLFW
            if (g_accion_pendiente == AccionPendiente::NINGUNA) {
                bool hay_datos;
                {
                    std::lock_guard<std::mutex> lk(g_packets_mutex);
                    hay_datos = !g_packets.empty();
                }
                if (g_is_capturing || hay_datos) {
                    g_accion_pendiente = AccionPendiente::SALIR;
                    g_abrir_popup_confirmacion = true;
                } else {
                    debe_cerrar_app = true;
                    continue;
                }
            }
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        glfwGetFramebufferSize(window, &ancho_ventana, &alto_ventana);
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2((float)ancho_ventana, (float)alto_ventana));

        ImGui::Begin("Consola Sniffer", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        // BARRA DE CONTROLES SUPERIOR
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.13f, 0.13f, 0.16f, 1.0f));
        float toolbar_height = g_show_dpi_search ? 120.0f : 85.0f;
        ImGui::BeginChild("##toolbar", ImVec2(0, toolbar_height), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        // Fila 1: Interfaz | estado | acciones
        ImGui::SetCursorPos(ImVec2(10, 10));

        // Etiqueta de estado
        if (g_is_capturing) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.10f, 0.42f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.10f, 0.42f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.10f, 0.42f, 0.15f, 1.0f));
            ImGui::Button("LIVE", ImVec2(60, 22));
            ImGui::PopStyleColor(3);
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.25f, 0.25f, 0.28f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.25f, 0.25f, 0.28f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.25f, 0.25f, 0.28f, 1.0f));
            ImGui::Button("ALTO", ImVec2(60, 22));
            ImGui::PopStyleColor(3);
        }

        ImGui::SameLine(0, 10);

        // Etiqueta y Combo
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2);
        ImGui::TextDisabled("Interfaz");
        ImGui::SameLine(0, 6);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2);
        std::string combo_preview = interfaces.empty() ? "Sin interfaces" : interfaces[interfaz_seleccionada_idx];
        ImGui::PushItemWidth(190);
        ImGui::PushStyleColor(ImGuiCol_FrameBg,        ImVec4(0.20f, 0.20f, 0.25f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.25f, 0.25f, 0.32f, 1.0f));
        if (ImGui::BeginCombo("##iface", combo_preview.c_str())) {
            for (int n = 0; n < (int)interfaces.size(); n++) {
                const bool is_sel = (interfaz_seleccionada_idx == n);
                if (ImGui::Selectable(interfaces[n].c_str(), is_sel)) {
                    if (n != interfaz_seleccionada_idx) {
                        bool hay_datos;
                        {
                            std::lock_guard<std::mutex> lk(g_packets_mutex);
                            hay_datos = !g_packets.empty();
                        }
                        if (g_is_capturing || hay_datos) {
                            // Hay captura activa o paquetes sin exportar: pedir confirmación antes de cambiar
                            g_interfaz_destino_idx = n;
                            g_accion_pendiente = AccionPendiente::CAMBIAR_INTERFAZ;
                            g_abrir_popup_confirmacion = true;
                        } else {
                            interfaz_seleccionada_idx = n;
                        }
                    }
                }
                if (is_sel) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
        ImGui::PopStyleColor(2);
        ImGui::PopItemWidth();

        ImGui::SameLine(0, 14);

        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddLine(
                ImVec2(p.x, p.y - 2), ImVec2(p.x, p.y + 22),
                IM_COL32(90, 90, 100, 200), 1.0f);
            ImGui::Dummy(ImVec2(1, 0));
        }
        ImGui::SameLine(0, 14);

        // Botón Iniciar / Detener
        if (!g_is_capturing) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.16f, 0.52f, 0.22f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.65f, 0.28f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.12f, 0.38f, 0.16f, 1.0f));
            if (ImGui::Button("Iniciar captura", ImVec2(130, 26)) && !interfaces.empty())
                IniciarHiloCaptura(interfaces[interfaz_seleccionada_idx]);
            ImGui::PopStyleColor(3);
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.68f, 0.14f, 0.14f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.84f, 0.18f, 0.18f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.10f, 0.10f, 1.0f));
            if (ImGui::Button("Detener captura", ImVec2(130, 26)))
                DetenerCaptura();
            ImGui::PopStyleColor(3);
        }

        ImGui::SameLine(0, 14);

        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddLine(
                ImVec2(p.x, p.y - 2), ImVec2(p.x, p.y + 22),
                IM_COL32(90, 90, 100, 200), 1.0f);
            ImGui::Dummy(ImVec2(1, 0));
        }
        ImGui::SameLine(0, 14);

        // Controles de Zoom
        {
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
            ImGui::TextDisabled("Zoom");
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 4);
            ImGui::SameLine(0, 6);

            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.26f, 0.26f, 0.30f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.34f, 0.34f, 0.40f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.20f, 0.20f, 0.24f, 1.0f));
            if (ImGui::Button("-##zoom", ImVec2(26, 26))) {
                g_zoom_nivel -= ZOOM_PASO;
                if (g_zoom_nivel < ZOOM_MIN) g_zoom_nivel = ZOOM_MIN;
            }
            ImGui::PopStyleColor(3);

            ImGui::SameLine(0, 4);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
            ImGui::Text("%d%%", (int)(g_zoom_nivel * 100.0f + 0.5f));
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 4);
            ImGui::SameLine(0, 4);

            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.26f, 0.26f, 0.30f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.34f, 0.34f, 0.40f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.20f, 0.20f, 0.24f, 1.0f));
            if (ImGui::Button("+##zoom", ImVec2(26, 26))) {
                g_zoom_nivel += ZOOM_PASO;
                if (g_zoom_nivel > ZOOM_MAX) g_zoom_nivel = ZOOM_MAX;
            }
            ImGui::PopStyleColor(3);

            ImGui::SameLine(0, 6);
            ImGui::PushStyleColor(ImGuiCol_Button,        g_zoom_nivel == 1.0f ? ImVec4(0.16f, 0.52f, 0.22f, 1.0f) : ImVec4(0.26f, 0.26f, 0.30f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, g_zoom_nivel == 1.0f ? ImVec4(0.20f, 0.62f, 0.26f, 1.0f) : ImVec4(0.34f, 0.34f, 0.40f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  g_zoom_nivel == 1.0f ? ImVec4(0.14f, 0.44f, 0.18f, 1.0f) : ImVec4(0.20f, 0.20f, 0.24f, 1.0f));
            if (ImGui::Button("Restablecer##zoom", ImVec2(0, 26))) g_zoom_nivel = 1.0f;
            ImGui::PopStyleColor(3);
        }

        ImGui::SameLine(0, 14);

        // Empujar vista/exportar/limpiar hacia la derecha
        float btn_right_x = ImGui::GetContentRegionAvail().x - 290;
        if (btn_right_x > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + btn_right_x);

        // Botón "Vista" -> abre popup con preferencias de apariencia del Área 1
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f, 0.30f, 0.34f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.40f, 0.40f, 0.46f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.22f, 0.22f, 0.26f, 1.0f));
        if (ImGui::Button("Vista", ImVec2(70, 26)))
            ImGui::OpenPopup("PopupVista");
        ImGui::PopStyleColor(3);

        if (ImGui::BeginPopup("PopupVista")) {
            ImGui::TextDisabled("Apariencia del Registro de Tráfico");
            ImGui::Separator();

            // Botón que se resalta en verde si es la opción activa
            auto OpcionBoton = [](const char* label, bool activo) -> bool {
                if (activo) {
                    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.16f, 0.52f, 0.22f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.62f, 0.26f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.14f, 0.44f, 0.18f, 1.0f));
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.26f, 0.26f, 0.30f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.34f, 0.34f, 0.40f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.20f, 0.20f, 0.24f, 1.0f));
                }
                bool clicked = ImGui::SmallButton(label);
                ImGui::PopStyleColor(3);
                return clicked;
            };

            if (ImGui::BeginTabBar("##VistaTabs")) {

                // Pestaña 1: Opciones generales
                if (ImGui::BeginTabItem("General")) {
                    ImGui::Spacing();
                    ImGui::Text("Colores de fondo");
                    ImGui::SameLine(150);

                    // Botón X: desactiva colores de protocolo y fuerza letra blanca
                    {
                        bool sin_color = !g_color_protocolo_activo;
                        ImGui::PushStyleColor(ImGuiCol_Button,        sin_color ? ImVec4(0.50f, 0.10f, 0.10f, 1.0f) : ImVec4(0.26f, 0.26f, 0.30f, 1.0f));
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, sin_color ? ImVec4(0.68f, 0.14f, 0.14f, 1.0f) : ImVec4(0.34f, 0.34f, 0.40f, 1.0f));
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  sin_color ? ImVec4(0.38f, 0.08f, 0.08f, 1.0f) : ImVec4(0.20f, 0.20f, 0.24f, 1.0f));
                        ImGui::PushStyleColor(ImGuiCol_Border, sin_color ? ImVec4(1.0f,1.0f,1.0f,1.0f) : ImVec4(0.0f,0.0f,0.0f,0.4f));
                        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, sin_color ? 2.5f : 1.0f);
                        if (ImGui::Button("##btn_x", ImVec2(20, 20))) {
                            if (g_color_protocolo_activo) {
                                g_text_color_idx_previo = g_table_text_color_idx;
                                g_table_text_color_idx = 2;
                            }
                            g_color_protocolo_activo = false;
                        }
                        ImGui::PopStyleVar();
                        ImGui::PopStyleColor(4);
                        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Sin color%s", sin_color ? " (actual)" : "");

                        // Dibujar X roja encima
                        ImVec2 p = ImGui::GetItemRectMin();
                        ImVec2 q = ImGui::GetItemRectMax();
                        ImDrawList* dl = ImGui::GetWindowDrawList();
                        ImU32 x_col = IM_COL32(230, 80, 80, 240);
                        dl->AddLine(ImVec2(p.x+4, p.y+4), ImVec2(q.x-4, q.y-4), x_col, 2.0f);
                        dl->AddLine(ImVec2(q.x-4, p.y+4), ImVec2(p.x+4, q.y-4), x_col, 2.0f);
                    }

                    ImGui::SameLine(0, 4);

                    // Botón palomita: reactiva colores y restaura el color de letra previo
                    {
                        bool con_color = g_color_protocolo_activo;
                        ImGui::PushStyleColor(ImGuiCol_Button,        con_color ? ImVec4(0.16f, 0.52f, 0.22f, 1.0f) : ImVec4(0.26f, 0.26f, 0.30f, 1.0f));
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, con_color ? ImVec4(0.20f, 0.62f, 0.26f, 1.0f) : ImVec4(0.34f, 0.34f, 0.40f, 1.0f));
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  con_color ? ImVec4(0.14f, 0.44f, 0.18f, 1.0f) : ImVec4(0.20f, 0.20f, 0.24f, 1.0f));
                        ImGui::PushStyleColor(ImGuiCol_Border, con_color ? ImVec4(1.0f,1.0f,1.0f,1.0f) : ImVec4(0.0f,0.0f,0.0f,0.4f));
                        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, con_color ? 2.5f : 1.0f);
                        if (ImGui::Button("##btn_check", ImVec2(20, 20))) {
                            if (!g_color_protocolo_activo)
                                g_table_text_color_idx = g_text_color_idx_previo;
                            g_color_protocolo_activo = true;
                        }
                        ImGui::PopStyleVar();
                        ImGui::PopStyleColor(4);
                        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Con color%s", con_color ? " (actual)" : "");

                        // Dibujar palomita verde encima
                        ImVec2 p = ImGui::GetItemRectMin();
                        ImVec2 q = ImGui::GetItemRectMax();
                        ImDrawList* dl = ImGui::GetWindowDrawList();
                        ImU32 chk_col = IM_COL32(100, 230, 120, 240);
                        float cx = p.x + (q.x - p.x) * 0.5f;
                        float cy = p.y + (q.y - p.y) * 0.5f;
                        dl->AddLine(ImVec2(p.x+3, cy),     ImVec2(cx-1,  q.y-4), chk_col, 2.0f);
                        dl->AddLine(ImVec2(cx-1,  q.y-4),  ImVec2(q.x-3, p.y+4), chk_col, 2.0f);
                    }

                    ImGui::Spacing();
                    ImGui::Text("Intensidad de fondo");
                    ImGui::SameLine(150);
                    for (int t = 0; t < 3; ++t) {
                        if (OpcionBoton(g_tone_names[t], g_table_bg_tone_idx == t)) g_table_bg_tone_idx = t;
                        if (t < 2) ImGui::SameLine();
                    }

                    ImGui::Spacing();
                    ImGui::Text("Color de letra");
                    ImGui::SameLine(150);
                    for (int t = 0; t < 3; ++t) {
                        if (OpcionBoton(g_text_color_names[t], g_table_text_color_idx == t)) g_table_text_color_idx = t;
                        if (t < 2) ImGui::SameLine();
                    }
                    ImGui::Spacing();
                    ImGui::EndTabItem();
                }

                // Pestaña 2: Color por protocolo
                if (ImGui::BeginTabItem("Colores por protocolo")) {
                    ImGui::Spacing();
                    ImGui::TextDisabled("Elige un color de la paleta para cada protocolo.");
                    ImGui::Spacing();

                    ImGui::BeginChild("##protocolos_scroll", ImVec2(420, 320), false);
                    // Una fila por protocolo: nombre más cuadrícula de 10 colores
                    for (int p = 0; p < NUM_PROTOCOLOS_CONFIG; ++p) {
                        ImGui::TextUnformatted(g_protocolo_colores[p].nombre);
                        ImGui::SameLine(95);

                        for (int c = 0; c < NUM_PALETA; ++c) {
                            bool es_actual = (g_protocolo_colores[p].paleta_idx == c);
                            ImGui::PushID(p * 100 + c);

                            ImVec4 sw = g_paleta_colores[c];
                            ImGui::PushStyleColor(ImGuiCol_Button, sw);
                            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(sw.x * 0.9f, sw.y * 0.9f, sw.z * 0.9f, 1.0f));
                            ImGui::PushStyleColor(ImGuiCol_ButtonActive, sw);

                            if (es_actual) {
                                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
                                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 2.5f);
                            } else {
                                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.0f, 0.0f, 0.0f, 0.4f));
                                ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
                            }

                            std::string tip = g_paleta_nombres[c];
                            if (ImGui::Button("##sw", ImVec2(20, 20))) {
                                g_protocolo_colores[p].paleta_idx = c;
                            }
                            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s%s", g_paleta_nombres[c], es_actual ? " (actual)" : "");

                            ImGui::PopStyleVar();
                            ImGui::PopStyleColor(4);
                            ImGui::PopID();
                            if (c < NUM_PALETA - 1) ImGui::SameLine(0, 4);
                        }
                    }
                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }

                ImGui::EndTabBar();
            }

            ImGui::EndPopup();
        }

        ImGui::SameLine(0, 10);

        {
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddLine(
                ImVec2(p.x, p.y - 2), ImVec2(p.x, p.y + 22),
                IM_COL32(90, 90, 100, 200), 1.0f);
            ImGui::Dummy(ImVec2(1, 0));
        }
        ImGui::SameLine(0, 10);

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.18f, 0.32f, 0.58f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.24f, 0.42f, 0.75f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.13f, 0.24f, 0.44f, 1.0f));
        if (ImGui::Button("Exportar CSV", ImVec2(110, 26)))
            exportar_csv();
        ImGui::PopStyleColor(3);

        ImGui::SameLine(0, 6);

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f, 0.22f, 0.08f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.46f, 0.36f, 0.10f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.20f, 0.16f, 0.06f, 1.0f));
        if (ImGui::Button("Limpiar", ImVec2(80, 26))) {
            bool hay_datos;
            {
                std::lock_guard<std::mutex> lk(g_packets_mutex);
                hay_datos = !g_packets.empty();
            }
            if (hay_datos) {
                g_accion_pendiente = AccionPendiente::LIMPIAR;
                g_abrir_popup_confirmacion = true;
            }
        }
        ImGui::PopStyleColor(3);

        // ZONA DE FILTROS (CON ACORDEÓN PARA DPI)
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Filtros de Cabecera:");
        
        // Fila 1: Filtros Clásicos
        ImGui::PushItemWidth(140); 
        ImGui::InputTextWithHint("##src_ip", "IP Origen...", filter_src_ip, IM_ARRAYSIZE(filter_src_ip));
        ImGui::SameLine();
        ImGui::InputTextWithHint("##dst_ip", "IP Destino...", filter_dst_ip, IM_ARRAYSIZE(filter_dst_ip));
        ImGui::SameLine();
        ImGui::InputTextWithHint("##src_port", "Puerto Origen...", filter_src_port, IM_ARRAYSIZE(filter_src_port));
        ImGui::SameLine();
        ImGui::InputTextWithHint("##dst_port", "Puerto Destino...", filter_dst_port, IM_ARRAYSIZE(filter_dst_port));
        ImGui::SameLine();
        ImGui::InputTextWithHint("##proto", "Protocolo (TCP)...", filter_protocol, IM_ARRAYSIZE(filter_protocol));
        ImGui::PopItemWidth(); 

        ImGui::SameLine();
        if (ImGui::Button("Limpiar Todos")) {
            filter_src_ip[0] = '\0';
            filter_dst_ip[0] = '\0';
            filter_src_port[0] = '\0';
            filter_dst_port[0] = '\0';
            filter_protocol[0] = '\0';
            filter_payload[0] = '\0';
        }

        // Botón Lupa
        ImGui::SameLine();
        
        // Si hay texto en el filtro pero está oculto
        bool filtro_oculto_activo = (!g_show_dpi_search && strlen(filter_payload) > 0);
        if (filtro_oculto_activo) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.4f, 0.0f, 1.0f)); 
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.5f, 0.1f, 1.0f));
        }

        // El texto del botón cambia dependiendo de si está abierto o cerrado
        if (ImGui::Button(g_show_dpi_search ? "[-] Cerrar DPI" : "Búsqueda Profunda")) {
            g_show_dpi_search = !g_show_dpi_search;
        }

        if (filtro_oculto_activo) {
            ImGui::PopStyleColor(2);
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "(!)");
        }

        // Fila 2: Búsqueda Profunda (SOLO SE DIBUJA SI EL BOTÓN ESTÁ ACTIVO)
        if (g_show_dpi_search) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.8f, 0.4f, 1.0f, 1.0f), "Inspección de Contenido (DPI):");
            
            ImGui::PushItemWidth(450); 
            ImGui::InputTextWithHint("##payload", "Buscar texto en los bytes (ej. login, password)...", filter_payload, IM_ARRAYSIZE(filter_payload));
            ImGui::PopItemWidth();
            
            ImGui::SameLine();
            if (ImGui::Button("Borrar Texto DPI")) {
                filter_payload[0] = '\0';
            }
        }

        ImGui::Separator();

        // Revisar si hay filtros puestos
        bool hay_filtros = filter_src_ip[0] || filter_dst_ip[0] || filter_src_port[0] || filter_dst_port[0] || filter_protocol[0];
        if (hay_filtros) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.45f, 0.12f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.62f, 0.16f, 0.16f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.32f, 0.08f, 0.08f, 1.0f));
            if (ImGui::Button("Borrar filtros", ImVec2(0, 22))) {
                filter_src_ip[0] = filter_dst_ip[0] = filter_src_port[0] =
                filter_dst_port[0] = filter_protocol[0] = '\0';
            }
            ImGui::PopStyleColor(3);
        }

        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::Separator();

        // ÁREA 1: REGISTRO DE TRÁFICO
        {
            int visibles = 0;
            {
                std::lock_guard<std::mutex> lk(g_packets_mutex);
                for (auto& p : g_packets) if (CumpleFiltros(p)) visibles++;
            }
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.5f, 1.0f), "Registro de Tráfico");
            ImGui::SameLine();
            ImGui::TextDisabled("(%d paquetes)", visibles);
        }
        
        // Inicialización de la altura si es el primer renderizado
        if (g_area1_height < 0) {
            g_area1_height = alto_ventana * 0.28f;
        }

        // Variable local para rastrear si el usuario estaba al fondo antes de procesar las filas
        bool estaba_al_fondo = false;

        // Contenedor propio que define la altura del panel (redimensionable con el splitter).
        // El scroll vertical real lo maneja la TABLA internamente (ImGuiTableFlags_ScrollY),
        // porque es la única forma en ImGui de tener un encabezado "pegado" (sticky) al hacer scroll.
        ImGui::BeginChild("Area1Container", ImVec2(0, g_area1_height), true, ImGuiWindowFlags_NoScrollbar);
        ImGui::SetWindowFontScale(g_zoom_nivel);

        if (ImGui::BeginTable("Trafico de la Red", 7,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Reorderable |   // Permite arrastrar columnas para reordenarlas
                ImGuiTableFlags_Resizable   |   // Permite ajustar el ancho de cada columna
                ImGuiTableFlags_ScrollY     |   // Habilita región interna con scroll más encabezado
                ImGuiTableFlags_SizingFixedFit,
                ImVec2(0, ImGui::GetContentRegionAvail().y))) {
            // La tabla con ScrollY crea su propia ventana interna de scroll, que NO hereda
            // el SetWindowFontScale del child padre (Area1Container). Por eso se aplica también aquí.
            ImGui::SetWindowFontScale(g_zoom_nivel);

            // NoHide impide que el usuario oculte/colapse por completo una columna desde el menú del header.
            // El segundo parámetro de WidthFixed es el ancho INICIAL; ImGuiTableColumnFlags_WidthFixed
            // respeta un ancho mínimo interno de ImGui (~ItemSpacing) al redimensionar, así nunca llega a 0.
            // "Informacion" usa WidthStretch para ocupar todo el espacio sobrante hacia la derecha.
            ImGui::TableSetupColumn("No.",         ImGuiTableColumnFlags_WidthFixed   | ImGuiTableColumnFlags_NoHide, 50.0f);
            ImGui::TableSetupColumn("Tiempo",      ImGuiTableColumnFlags_WidthFixed   | ImGuiTableColumnFlags_NoHide, 110.0f); // Más ancho para el formato 1234.567890
            ImGui::TableSetupColumn("IP Origen",   ImGuiTableColumnFlags_WidthFixed   | ImGuiTableColumnFlags_NoHide, 130.0f);
            ImGui::TableSetupColumn("IP Destino",  ImGuiTableColumnFlags_WidthFixed   | ImGuiTableColumnFlags_NoHide, 130.0f);
            ImGui::TableSetupColumn("Protocolo",   ImGuiTableColumnFlags_WidthFixed   | ImGuiTableColumnFlags_NoHide, 80.0f);
            ImGui::TableSetupColumn("Longitud",    ImGuiTableColumnFlags_WidthFixed   | ImGuiTableColumnFlags_NoHide, 70.0f);
            ImGui::TableSetupColumn("Informacion", ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_NoHide, 280.0f);
            ImGui::TableSetupScrollFreeze(0, 1); // Congela la fila de encabezados (siempre visible al hacer scroll)
            ImGui::TableHeadersRow();

            // Verificar la posición del scroll vertical DE LA TABLA antes de iterar
            // (con ScrollY activo, el scroll vive en la región interna de la tabla, no en el child)
            float scroll_y = ImGui::GetScrollY();
            float max_scroll_y = ImGui::GetScrollMaxY();
            if (scroll_y >= max_scroll_y - 5.0f) {
                estaba_al_fondo = true;
            }

            // Exclusión mutua para leer los paquetes capturados
            g_packets_mutex.lock();
            for (size_t i = 0; i < g_packets.size(); ++i) {
                const PacketData& paquete = g_packets[i];

                if (!CumpleFiltros(paquete)) continue;

                // Color base tomado de la configuración del usuario
                ImVec4 text_color = g_text_color_options[g_table_text_color_idx];
                ImVec4 base_pastel = ColorParaProtocolo(paquete.protocol);
                bool usar_color_fondo = g_color_protocolo_activo;
                ImU32 bg_color = ImGui::GetColorU32(AplicarTono(base_pastel));

                // Si esta fila específica es la seleccionada por el usuario,
                // sobreescribe con el color de selección azul de ImGUI
                bool is_selected = (g_selected_packet_idx == (int)i);
                if (is_selected) {
                    bg_color = ImGui::GetColorU32(ImVec4(0.26f, 0.59f, 0.98f, 0.85f));
                    text_color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                    usar_color_fondo = true;
                }

                ImGui::TableNextRow();

                // Dibujar celdas poniendo el color de fondo persistente y el texto correspondiente
                for (int col = 0; col < 7; ++col) {
                    ImGui::TableSetColumnIndex(col);
                    // Esto pinta el fondo completo de la celda de forma permanente sin importar el ratón
                    if (usar_color_fondo)
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_CellBg, bg_color);

                    ImGui::PushStyleColor(ImGuiCol_Text, text_color);
                    
                    if (col == 0) {
                        char label[32]; sprintf(label, "%d", paquete.id);
                        // El Selectable se mantiene transparente para que no altere los colores manuales de celda
                        ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0,0,0,0));
                        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(1.0f, 1.0f, 1.0f, 0.15f));
                        
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

            // Ejecución del autoscroll DENTRO de la región de la tabla (es donde vive el scroll real)
            // Si el programa está capturando y el usuario no ha subido manualmente, se forza la vista al fondo
            if (g_is_capturing && estaba_al_fondo) {
                ImGui::SetScrollHereY(1.0f);
            }

            ImGui::EndTable();
        }

        ImGui::EndChild();

        // SPLITTER ENTRE ÁREA 1 y LAS ÁREAS 2 Y 3
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
        float offset_inferior = g_show_dpi_search ? 225.0f : 195.0f;
        float lower_height = ImGui::GetContentRegionAvail().y - 14.0f; 
        if (lower_height < 100.0f) lower_height = 100.0f;

        ImGui::Columns(2, "LowerPanels", true);

        // Datos por capas
        ImGui::TextColored(ImVec4(1.0f, 0.65f, 0.10f, 1.0f), "Análisis por Capas  ");
        ImGui::SameLine();
        ImGui::TextDisabled("OSI / TCP-IP");
        ImGui::BeginChild("TreePanel", ImVec2(0, lower_height), true, ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::SetWindowFontScale(g_zoom_nivel);
        
        //Exclusión para el paquete seleccionado
        g_packets_mutex.lock();
        // Información en el área 2
        if (g_selected_packet_idx != -1 && g_selected_packet_idx < (int)g_packets.size()) {
            const PacketData& paquete = g_packets[g_selected_packet_idx];

            if (ImGui::TreeNode("Capa II: Enlace de Datos")) {
                ImGui::Text("MAC Origen:  %s", paquete.mac_src.c_str());
                ImGui::Text("MAC Destino: %s", paquete.mac_dst.c_str());
                ImGui::Text("EtherType:   0x%04X  (%s)",
                    paquete.eth_type,
                    paquete.eth_type == 0x0800 ? "IPv4" :
                    paquete.eth_type == 0x0806 ? "ARP"  :
                    paquete.eth_type == 0x86DD ? "IPv6" :
                    paquete.eth_type == 0x8100 ? "VLAN 802.1Q" :
                    paquete.eth_type == 0x8847 ? "MPLS Unicast" :
                    paquete.eth_type == 0x8848 ? "MPLS Multicast" :
                    paquete.eth_type == 0x88CC ? "LLDP" : "Otro");
                ImGui::TreePop();
            }
            if (paquete.eth_type == ETHERTYPE_IP && ImGui::TreeNode("Capa III: Red con IPv4")) {
                ImGui::Text("Version: IPv%d", paquete.ip_version);
                ImGui::Text("Longitud total: %d bytes", paquete.ip_len);
                ImGui::Text("IP Origen: %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino: %s", paquete.dest_ip.c_str());
                ImGui::Text("TTL (Tiempo de vida): %d", paquete.ip_ttl);
                ImGui::Text("Protocolo interno (número): %d", paquete.ip_proto);
                // Descripción legible del número de protocolo IP
                const char* proto_desc = "Desconocido";
                // Descripción protocolos
                switch (paquete.ip_proto) {
                    case   1: proto_desc = "ICMP - Internet Control Message Protocol"; break;
                    case   2: proto_desc = "IGMP - Internet Group Management Protocol"; break;
                    case   4: proto_desc = "IP-in-IP Encapsulation (Tunnel)"; break;
                    case   6: proto_desc = "TCP - Transmission Control Protocol"; break;
                    case   8: proto_desc = "EGP - Exterior Gateway Protocol"; break;
                    case   9: proto_desc = "IGRP - Cisco Interior Gateway Routing"; break;
                    case  17: proto_desc = "UDP - User Datagram Protocol"; break;
                    case  41: proto_desc = "IPv6 encapsulado sobre IPv4"; break;
                    case  43: proto_desc = "IPv6 Routing Header"; break;
                    case  44: proto_desc = "IPv6 Fragment Header"; break;
                    case  46: proto_desc = "RSVP - Resource Reservation Protocol"; break;
                    case  47: proto_desc = "GRE - Generic Routing Encapsulation"; break;
                    case  50: proto_desc = "ESP - IPSec Encapsulating Security Payload"; break;
                    case  51: proto_desc = "AH - IPSec Authentication Header"; break;
                    case  58: proto_desc = "ICMPv6 - ICMP para IPv6"; break;
                    case  59: proto_desc = "IPv6 No Next Header"; break;
                    case  60: proto_desc = "IPv6 Destination Options"; break;
                    case  88: proto_desc = "EIGRP - Enhanced Interior Gateway Routing (Cisco)"; break;
                    case  89: proto_desc = "OSPF - Open Shortest Path First"; break;
                    case  97: proto_desc = "ETHERIP - Ethernet-within-IP Encapsulation"; break;
                    case  98: proto_desc = "ENCAP - Encapsulation Header"; break;
                    case 103: proto_desc = "PIM - Protocol Independent Multicast"; break;
                    case 108: proto_desc = "IPComp - IP Payload Compression"; break;
                    case 112: proto_desc = "VRRP - Virtual Router Redundancy Protocol"; break;
                    case 115: proto_desc = "L2TP - Layer 2 Tunneling Protocol"; break;
                    case 132: proto_desc = "SCTP - Stream Control Transmission Protocol"; break;
                    case 137: proto_desc = "MPLS-in-IP"; break;
                    case 139: proto_desc = "HIP - Host Identity Protocol"; break;
                    case 140: proto_desc = "Shim6 - Site Multihoming by IPv6"; break;
                    case 253: proto_desc = "Prueba / Experimentación (RFC 3692)"; break;
                    case 254: proto_desc = "Prueba / Experimentación (RFC 3692)"; break;
                }
                ImGui::TextColored(ImVec4(0.7f, 0.9f, 0.7f, 1.0f), "  -> %s", proto_desc);
                ImGui::TreePop();
            }

            // Capa de Transporte (TCP / UDP / SCTP / app detectada por puerto)
            bool es_app = !paquete.app_protocol.empty();
            // Para protocolos de aplicación, la capa IV muestra TCP/UDP según ip_proto
            std::string trans_proto = (es_app && paquete.ip_proto == 6) ? "TCP" :
                                      (es_app && paquete.ip_proto == 17) ? "UDP" :
                                      paquete.protocol;
            string trans_lbl = "Capa IV: Transporte " + trans_proto;

            if ((paquete.protocol == "TCP" || paquete.protocol == "UDP" || paquete.protocol == "SCTP" || es_app)
                && ImGui::TreeNode(trans_lbl.c_str())) {
                ImGui::Text("Puerto Origen:  %d", paquete.src_port);
                ImGui::Text("Puerto Destino: %d", paquete.dst_port);
                if (paquete.protocol == "TCP") {
                    ImGui::Text("Flags TCP:");
                    ImGui::SameLine();
                    auto Flag = [&](const char* name, uint8_t bit, ImVec4 col) {
                        if (paquete.tcp_flags & bit)
                            ImGui::TextColored(col, "[%s]", name);
                        else
                            ImGui::TextDisabled("[%s]", name);
                        ImGui::SameLine(0, 4);
                    };
                    Flag("SYN", 0x02, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
                    Flag("ACK", 0x10, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
                    Flag("FIN", 0x01, ImVec4(1.0f, 0.8f, 0.3f, 1.0f));
                    Flag("RST", 0x04, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
                    Flag("PSH", 0x08, ImVec4(0.9f, 0.6f, 1.0f, 1.0f));
                    Flag("URG", 0x20, ImVec4(1.0f, 0.6f, 0.2f, 1.0f));
                    ImGui::NewLine();
                }
                if (!paquete.app_protocol.empty())
                    ImGui::TextColored(ImVec4(0.6f, 0.9f, 1.0f, 1.0f), "Protocolo de aplicacion detectado: %s", paquete.app_protocol.c_str());
                ImGui::TreePop();
            }
            if (es_app) {
                std::string app_lbl = "Capa VII: " + paquete.app_protocol + " (Aplicacion)";
                if (ImGui::TreeNode(app_lbl.c_str())) {
                    ImGui::Text("IP Origen:  %s : %d", paquete.source_ip.c_str(), paquete.src_port);
                    ImGui::Text("IP Destino: %s : %d", paquete.dest_ip.c_str(),   paquete.dst_port);
                    // Notas específicas por protocolo
                    if (paquete.app_protocol == "SSH")
                        ImGui::TextColored(ImVec4(0.7f,0.6f,1.0f,1.0f), "Acceso remoto cifrado. El payload no es legible.");
                    else if (paquete.app_protocol == "Telnet")
                        ImGui::TextColored(ImVec4(1.0f,0.5f,0.5f,1.0f), "Acceso remoto SIN cifrado. El payload es texto legible.");
                    else if (paquete.app_protocol == "RDP")
                        ImGui::TextColored(ImVec4(0.7f,0.5f,1.0f,1.0f), "Escritorio remoto Windows (cifrado).");
                    else if (paquete.app_protocol == "VNC")
                        ImGui::TextColored(ImVec4(0.7f,0.5f,1.0f,1.0f), "Control remoto de escritorio.");
                    else if (paquete.app_protocol == "HTTP")
                        ImGui::TextColored(ImVec4(0.5f,0.8f,1.0f,1.0f), "Trafico web sin cifrar. Payload legible en hexdump.");
                    else if (paquete.app_protocol == "HTTPS" || paquete.app_protocol == "HTTPS-Alt")
                        ImGui::TextColored(ImVec4(0.5f,1.0f,0.6f,1.0f), "Trafico web cifrado con TLS/SSL.");
                    else if (paquete.app_protocol == "HTTP-Alt")
                        ImGui::TextColored(ImVec4(0.5f,0.8f,1.0f,1.0f), "HTTP en puerto alternativo.");
                    else if (paquete.app_protocol == "DNS" || paquete.app_protocol == "mDNS")
                        ImGui::TextColored(ImVec4(1.0f,0.95f,0.4f,1.0f), "Resolucion de nombres de dominio.");
                    else if (paquete.app_protocol == "SMTP" || paquete.app_protocol == "SMTPS" || paquete.app_protocol == "SMTP-Sub")
                        ImGui::TextColored(ImVec4(1.0f,0.7f,0.3f,1.0f), "Envio de correo electronico.");
                    else if (paquete.app_protocol == "POP3" || paquete.app_protocol == "POP3S")
                        ImGui::TextColored(ImVec4(1.0f,0.7f,0.3f,1.0f), "Recepcion de correo (POP3).");
                    else if (paquete.app_protocol == "IMAP" || paquete.app_protocol == "IMAPS")
                        ImGui::TextColored(ImVec4(1.0f,0.7f,0.3f,1.0f), "Acceso a correo en servidor (IMAP).");
                    else if (paquete.app_protocol == "FTP" || paquete.app_protocol == "FTP-Data" || paquete.app_protocol == "FTPS" || paquete.app_protocol == "FTPS-Data" || paquete.app_protocol == "TFTP")
                        ImGui::TextColored(ImVec4(0.3f,1.0f,0.9f,1.0f), "Transferencia de archivos.");
                    else if (paquete.app_protocol == "DHCP-Srv" || paquete.app_protocol == "DHCP-Cli" || paquete.app_protocol == "DHCPv6-Cli" || paquete.app_protocol == "DHCPv6-Srv")
                        ImGui::TextColored(ImVec4(1.0f,0.95f,0.4f,1.0f), "Asignacion dinamica de direcciones IP.");
                    else if (paquete.app_protocol == "NTP")
                        ImGui::TextColored(ImVec4(1.0f,0.95f,0.4f,1.0f), "Sincronizacion de tiempo de red.");
                    else if (paquete.app_protocol == "SNMP" || paquete.app_protocol == "SNMP-Trap")
                        ImGui::TextColored(ImVec4(0.7f,1.0f,0.5f,1.0f), "Gestion y monitoreo de dispositivos de red.");
                    else if (paquete.app_protocol == "Syslog")
                        ImGui::TextColored(ImVec4(0.7f,1.0f,0.5f,1.0f), "Registro de eventos del sistema.");
                    else if (paquete.app_protocol == "SMB" || paquete.app_protocol == "NetBIOS-NS" || paquete.app_protocol == "NetBIOS-DG" || paquete.app_protocol == "NetBIOS-SS")
                        ImGui::TextColored(ImVec4(0.8f,0.8f,0.8f,1.0f), "Comparticion de archivos e impresoras en red Windows.");
                    else if (paquete.app_protocol == "MySQL" || paquete.app_protocol == "PostgreSQL" || paquete.app_protocol == "MSSQL" || paquete.app_protocol == "Oracle" || paquete.app_protocol == "Redis" || paquete.app_protocol == "MongoDB")
                        ImGui::TextColored(ImVec4(1.0f,0.5f,0.5f,1.0f), "Trafico de base de datos.");
                    else if (paquete.app_protocol == "SIP" || paquete.app_protocol == "SIPS")
                        ImGui::TextColored(ImVec4(0.7f,0.5f,1.0f,1.0f), "Protocolo de inicio de sesion VoIP.");
                    else if (paquete.app_protocol == "OpenVPN" || paquete.app_protocol == "IKE" || paquete.app_protocol == "IPSec-NAT")
                        ImGui::TextColored(ImVec4(0.5f,1.0f,0.6f,1.0f), "Trafico VPN cifrado.");
                    else if (paquete.app_protocol == "BGP")
                        ImGui::TextColored(ImVec4(0.7f,0.6f,1.0f,1.0f), "Protocolo de enrutamiento entre sistemas autonomos.");
                    else if (paquete.app_protocol == "LDAP" || paquete.app_protocol == "LDAPS")
                        ImGui::TextColored(ImVec4(0.7f,1.0f,0.5f,1.0f), "Servicio de directorio (Active Directory, OpenLDAP).");
                    else if (paquete.app_protocol == "Kerberos")
                        ImGui::TextColored(ImVec4(0.7f,0.6f,1.0f,1.0f), "Autenticacion de red Kerberos.");
                    else if (paquete.app_protocol == "NFS")
                        ImGui::TextColored(ImVec4(0.3f,1.0f,0.9f,1.0f), "Sistema de archivos de red (Network File System).");
                    else if (paquete.app_protocol == "RPC")
                        ImGui::TextColored(ImVec4(0.8f,0.8f,0.8f,1.0f), "Llamada a procedimiento remoto.");
                    else if (paquete.app_protocol == "BitTorrent")
                        ImGui::TextColored(ImVec4(1.0f,0.5f,0.5f,1.0f), "Transferencia P2P BitTorrent.");
                    ImGui::TreePop();
                }
            }
            // Información extra para protocolos de red/enrutamiento
            if (paquete.protocol == "ICMP" && ImGui::TreeNode("Capa III: ICMP")) {
                ImGui::Text("IP Origen: %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino: %s", paquete.dest_ip.c_str());
                ImGui::Text("TTL: %d", paquete.ip_ttl);
                ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.4f, 1.0f), "Protocolo de control y diagnóstico de red.");
                ImGui::TreePop();
            }
            if (paquete.protocol == "IGMP" && ImGui::TreeNode("Capa III: IGMP (Multicast)")) {
                ImGui::Text("IP Origen: %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino: %s", paquete.dest_ip.c_str());
                ImGui::TextColored(ImVec4(0.6f, 1.0f, 0.6f, 1.0f), "Gestión de grupos de multidifusión (multicast).");
                ImGui::TreePop();
            }
            if (paquete.protocol == "OSPF" && ImGui::TreeNode("Capa III: OSPF (Routing)")) {
                ImGui::Text("IP Origen (Router): %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino: %s", paquete.dest_ip.c_str());
                ImGui::Text("TTL: %d", paquete.ip_ttl);
                ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.4f, 1.0f), "Protocolo de enrutamiento de estado de enlace.");
                ImGui::TreePop();
            }
            if (paquete.protocol == "EIGRP" && ImGui::TreeNode("Capa III: EIGRP (Cisco Routing)")) {
                ImGui::Text("IP Origen (Router): %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino: %s", paquete.dest_ip.c_str());
                ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "Protocolo de enrutamiento avanzado de Cisco.");
                ImGui::TreePop();
            }
            if ((paquete.protocol == "GRE" || paquete.protocol == "L2TP")
                && ImGui::TreeNode(("Capa III: " + paquete.protocol + " (Tunneling)").c_str())) {
                ImGui::Text("IP Origen del Túnel: %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino del Túnel: %s", paquete.dest_ip.c_str());
                ImGui::Text("TTL: %d", paquete.ip_ttl);
                ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Protocolo de encapsulamiento / túnel VPN.");
                ImGui::TreePop();
            }
            if ((paquete.protocol == "ESP" || paquete.protocol == "AH")
                && ImGui::TreeNode(("Capa III: " + paquete.protocol + " (IPSec)").c_str())) {
                ImGui::Text("IP Origen: %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino: %s", paquete.dest_ip.c_str());
                ImGui::Text("TTL: %d", paquete.ip_ttl);
                if (paquete.protocol == "ESP")
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "IPSec ESP: Datos cifrados (confidencialidad + integridad).");
                else
                    ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.5f, 1.0f), "IPSec AH: Solo autenticación, sin cifrado.");
                ImGui::TreePop();
            }
            if (paquete.protocol == "PIM" && ImGui::TreeNode("Capa III: PIM (Multicast Routing)")) {
                ImGui::Text("IP Origen: %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino: %s", paquete.dest_ip.c_str());
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.8f, 1.0f), "Enrutamiento de multicast independiente del protocolo.");
                ImGui::TreePop();
            }
            if (paquete.protocol == "VRRP" && ImGui::TreeNode("Capa III: VRRP (Redundancia)")) {
                ImGui::Text("IP Origen (Router): %s", paquete.source_ip.c_str());
                ImGui::Text("IP Destino: %s", paquete.dest_ip.c_str());
                ImGui::TextColored(ImVec4(0.7f, 0.7f, 1.0f, 1.0f), "Protocolo de redundancia de router virtual.");
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

        // Datos Hexadecimales
        ImGui::TextColored(ImVec4(0.85f, 0.45f, 1.0f, 1.0f), "Volcado de Bytes");
        ImGui::SameLine();
        ImGui::TextDisabled("(hex / ASCII)");
        ImGui::BeginChild("HexPanel", ImVec2(0, lower_height), true, ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::SetWindowFontScale(g_zoom_nivel);
        
        // Otra exclusión mutua
        g_packets_mutex.lock();
        if (g_selected_packet_idx != -1 && g_selected_packet_idx < (int)g_packets.size()) {
            dibujar_hexdump(g_packets[g_selected_packet_idx].raw_bytes);
        } else {
            ImGui::Text("Selecciona un paquete para ver su contenido en hexadecimal");
        }
        g_packets_mutex.unlock();
        // Fin
        
        ImGui::EndChild();
        ImGui::Columns(1);

        // Popup modal de confirmación (Cambiar interfaz / Limpiar / Salir)
        if (g_abrir_popup_confirmacion) {
            ImGui::OpenPopup("##ModalConfirmacion");
            g_abrir_popup_confirmacion = false;
        }

        // Los textos de los botones dependen de la acción pendiente; se resuelven aquí,
        // ANTES de fijar el tamaño del modal, para poder medir su ancho real con la fuente actual
        // y que el modal nunca quede más angosto que el contenido
        const char* texto_guardar_modal = (g_accion_pendiente == AccionPendiente::LIMPIAR) ? "Guardar y limpiar" : "Guardar y continuar";
        const char* texto_sin_guardar_modal = "Sin guardar";
        if (g_accion_pendiente == AccionPendiente::CAMBIAR_INTERFAZ) texto_sin_guardar_modal = "Cambiar sin guardar";
        else if (g_accion_pendiente == AccionPendiente::LIMPIAR)     texto_sin_guardar_modal = "Limpiar sin guardar";
        else if (g_accion_pendiente == AccionPendiente::SALIR)       texto_sin_guardar_modal = "Salir sin guardar";

        const float padding_boton_modal = 28.0f;
        float ancho_boton_modal = ImGui::CalcTextSize("Cancelar").x;
        ancho_boton_modal = std::max(ancho_boton_modal, ImGui::CalcTextSize(texto_guardar_modal).x);
        ancho_boton_modal = std::max(ancho_boton_modal, ImGui::CalcTextSize(texto_sin_guardar_modal).x);
        ancho_boton_modal += padding_boton_modal;

        // Ancho total: 3 botones + 2 separaciones entre ellos + márgenes internos del modal (~32px)
        float ancho_modal = std::max(460.0f, ancho_boton_modal * 3.0f + ImGui::GetStyle().ItemSpacing.x * 2.0f + 32.0f);

        // Centrar el modal en la pantalla
        ImGui::SetNextWindowPos(ImVec2(ancho_ventana * 0.5f, alto_ventana * 0.5f), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
        ImGui::SetNextWindowSize(ImVec2(ancho_modal, 0));

        if (ImGui::BeginPopupModal("##ModalConfirmacion", nullptr,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) {

            // Conteo de paquetes para mostrar en el mensaje
            int total_paquetes;
            {
                std::lock_guard<std::mutex> lk(g_packets_mutex);
                total_paquetes = (int)g_packets.size();
            }

            // Encabezado e ícono según el tipo de acción
            const char* titulo = "";
            std::string mensaje;
            switch (g_accion_pendiente) {
                case AccionPendiente::CAMBIAR_INTERFAZ:
                    titulo = "Cambiar interfaz de red";
                    mensaje = "Tienes " + std::to_string(total_paquetes) + " paquete(s) capturado(s).\n"
                               "Cambiar de interfaz detendrá la captura actual y, si continuas,\n"
                               "se perderá el registro actual a menos que lo guardes primero.";
                    break;
                case AccionPendiente::LIMPIAR:
                    titulo = "Limpiar registro de tráfico";
                    mensaje = "Estás a punto de borrar " + std::to_string(total_paquetes) + " paquete(s).\n"
                               "Esta acción no se puede deshacer.";
                    break;
                case AccionPendiente::SALIR:
                    titulo = "Salir del Packet Sniffeador";
                    mensaje = "Tienes " + std::to_string(total_paquetes) + " paquete(s) capturado(s) sin guardar"
                               + std::string(g_is_capturing ? " y una captura en curso.\n" : ".\n")
                               + "Si sales ahora, esta información se perderá.";
                    break;
                default: break;
            }

            ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.2f, 1.0f), "%s", titulo);
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::TextWrapped("%s", mensaje.c_str());
            ImGui::Spacing();
            ImGui::Spacing();

            // Botón Cancelar
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f, 0.30f, 0.34f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.40f, 0.40f, 0.46f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.22f, 0.22f, 0.26f, 1.0f));
            if (ImGui::Button("Cancelar", ImVec2(ancho_boton_modal, 30))) {
                g_accion_pendiente = AccionPendiente::NINGUNA;
                g_interfaz_destino_idx = -1;
                ImGui::CloseCurrentPopup();
            }
            ImGui::PopStyleColor(3);

            ImGui::SameLine();

            // Botón Guardar
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.18f, 0.32f, 0.58f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.24f, 0.42f, 0.75f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.13f, 0.24f, 0.44f, 1.0f));
            if (ImGui::Button(texto_guardar_modal, ImVec2(ancho_boton_modal, 30))) {
                exportar_csv();
                EjecutarAccionPendiente(interfaz_seleccionada_idx, debe_cerrar_app);
            }
            ImGui::PopStyleColor(3);

            // Botón "continuar sin guardar"
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.68f, 0.14f, 0.14f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.84f, 0.18f, 0.18f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.10f, 0.10f, 1.0f));

            if (ImGui::Button(texto_sin_guardar_modal, ImVec2(ancho_boton_modal, 30))) {
                EjecutarAccionPendiente(interfaz_seleccionada_idx, debe_cerrar_app);
            }
            ImGui::PopStyleColor(3);

            ImGui::EndPopup();
        }

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