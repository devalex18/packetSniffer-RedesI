#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>
#include <atomic>
#include <pcap.h>

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

    // Contenido RAW (Área 3)
    std::vector<uint8_t> raw_bytes;
};

// Variables globales compartidas entre el Sniffer y la Interfaz Gráfica
extern std::vector<PacketData> g_packets;
extern std::mutex g_packets_mutex;        // Protege el vector al insertar desde el hilo
extern std::atomic<bool> g_is_capturing;  // Control seguro del estado del hilo
extern int g_packet_id_counter;           // Contador incremental de paquetes

// Funciones del módulo de red
bool IniciarHiloCaptura(const std::string& interfaz);
void DetenerCaptura();
std::vector<std::string> ObtenerInterfacesRed();

#endif // SNIFFER_H