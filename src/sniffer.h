#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>
#include <atomic>
#include <pcap.h>
#include <sys/time.h>

#define ETHERTYPE_IP 0x0800

// Estructura para almacenar los datos del paquete de forma procesada
struct PacketData {
    int id;
    std::string timestamp;
    std::string source_ip;
    std::string dest_ip;
    std::string protocol;
    uint32_t length;
    std::string info;
    
    // Desglose de capas para el árbol (Área 2)
    std::string mac_src;
    std::string mac_dst;
    uint16_t eth_type;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    uint16_t src_port;
    uint16_t dst_port;

    // Protocolo de aplicación detectado por puerto (SSH, HTTP, DNS…); vacío si no se reconoce
    std::string app_protocol;

    // Flags TCP: SYN, ACK, FIN, RST, PSH, URG (bitmask sobre los 6 bits bajos)
    uint8_t tcp_flags = 0;

    // Versión IP del paquete (4 o 6) y longitud total del datagrama IP
    uint8_t  ip_version = 0;
    uint16_t ip_len     = 0;

    // Contenido RAW (Área 3)
    std::vector<uint8_t> raw_bytes;
};

// Variables globales compartidas entre el Sniffer y la Interfaz Gráfica
extern std::vector<PacketData> g_packets;
extern std::mutex g_packets_mutex;        // Protege el vector al insertar desde el hilo
extern std::atomic<bool> g_is_capturing;  // Control seguro del estado del hilo
extern int g_packet_id_counter;           // Contador incremental de paquetes

// Timestamp del primer paquete de la sesión actual
extern struct timeval g_capture_start_time;

// Funciones del módulo de red
bool IniciarHiloCaptura(const std::string& interfaz);
void DetenerCaptura();
std::vector<std::string> ObtenerInterfacesRed();

#endif // SNIFFER_H