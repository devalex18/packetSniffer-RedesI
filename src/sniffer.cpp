#include "sniffer.h"
#include <iostream>
#include <thread>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ctime>

// Definición de variables globales
std::vector<PacketData> g_packets;
std::mutex g_packets_mutex;
std::atomic<bool> g_is_capturing(false);
int g_packet_id_counter = 1;

std::thread capture_thread;
pcap_t* pcap_handle = nullptr;

// Obtener la lista de tarjetas de red disponibles en Linux
std::vector<std::string> ObtenerInterfacesRed() {
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            interfaces.push_back(d->name);
        }
        pcap_freealldevs(alldevs);
    }
    return interfaces;
}

// Callback obligatorio de libpcap que se ejecuta por cada paquete detectado
void PacketCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (!g_is_capturing) return;

    PacketData pkt;
    pkt.id = g_packet_id_counter++;
    pkt.length = pkthdr->len;

    // Obtener Marca de Tiempo (Timestamp o Time)
    time_t rawtime = pkthdr->ts.tv_sec;
    struct tm* timeinfo = localtime(&rawtime);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo); // Convertir a formato HH:MM:SS
    pkt.timestamp = std::string(time_str);

    // Guardar el contenido RAW completo
    pkt.raw_bytes.assign(packet, packet + pkthdr->caplen);

    // Decodificar Capa de Enlace (Ethernet II), mostrado en área 2
    struct ether_header* eth = (struct ether_header*)packet;
    char mac_src_str[18], mac_dst_str[18];
    snprintf(mac_src_str, sizeof(mac_src_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
             eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    snprintf(mac_dst_str, sizeof(mac_dst_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
             eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    pkt.mac_src = mac_src_str;
    pkt.mac_dst = mac_dst_str;
    pkt.eth_type = ntohs(eth->ether_type);

    // DECODIFICACIÓN DE LA CAPA DE RED
    if (pkt.eth_type == ETHERTYPE_IP) { // 0x0800 - IPv4 Convencional
        struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ether_header));
        
        char src_ip_arr[INET_ADDRSTRLEN];
        char dst_ip_arr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), src_ip_arr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->daddr), dst_ip_arr, INET_ADDRSTRLEN);
        
        pkt.source_ip = src_ip_arr;
        pkt.dest_ip = dst_ip_arr;
        pkt.ip_ttl = ip->ttl;
        pkt.ip_proto = ip->protocol;

        size_t ip_header_len = ip->ihl * 4;
        const u_char* payload = packet + sizeof(struct ether_header) + ip_header_len;

        // Decodificar Capa de Transporte sobre IPv4
        if (ip->protocol == IPPROTO_TCP) {
            pkt.protocol = "TCP";
            struct tcphdr* tcp = (struct tcphdr*)payload;
            pkt.src_port = ntohs(tcp->source);
            pkt.dst_port = ntohs(tcp->dest);
            pkt.info = "Puerto Origen: " + std::to_string(pkt.src_port) + " -> Puerto Destino: " + std::to_string(pkt.dst_port);
        } 
        else if (ip->protocol == IPPROTO_UDP) {
            pkt.protocol = "UDP";
            struct udphdr* udp = (struct udphdr*)payload;
            pkt.src_port = ntohs(udp->source);
            pkt.dst_port = ntohs(udp->dest);
            pkt.info = "Puerto Origen: " + std::to_string(pkt.src_port) + " -> Puerto Destino: " + std::to_string(pkt.dst_port);
        } 
        else if (ip->protocol == IPPROTO_ICMP) {
            pkt.protocol = "ICMP";
            struct icmphdr* icmp = (struct icmphdr*)payload;
            pkt.src_port = 0; pkt.dst_port = 0;
            pkt.info = "Tipo ICMP: " + std::to_string(icmp->type) + " Codigo: " + std::to_string(icmp->code);
        } 
        else {
            pkt.protocol = "Otros (IPv4)";
            pkt.info = "Protocolo IP nativo: " + std::to_string(ip->protocol);
        }
    } 
    else if (pkt.eth_type == 0x0806) { // TRÁFICO ARP (Address Resolution Protocol)
        pkt.protocol = "ARP";
        
        // Estructura de cabecera ARP básica (28 bytes estándar)
        const u_char* arp_header = packet + sizeof(struct ether_header);
        uint16_t op_code = (arp_header[6] << 8) | arp_header[7]; // Operación: 1 para Request, 2 para Reply
        
        // Punteros internos para extraer IPs legibles dentro del cuerpo ARP
        char sender_ip[16];
        char target_ip[16];
        snprintf(sender_ip, sizeof(sender_ip), "%d.%d.%d.%d", arp_header[14], arp_header[15], arp_header[16], arp_header[17]);
        snprintf(target_ip, sizeof(target_ip), "%d.%d.%d.%d", arp_header[24], arp_header[25], arp_header[26], arp_header[27]);
        
        pkt.source_ip = sender_ip;
        pkt.dest_ip = target_ip;
        pkt.src_port = 0; pkt.dst_port = 0;
        
        if (op_code == 1) {
            pkt.info = "Who has " + std::string(target_ip) + "? Tell " + std::string(sender_ip);
        } else if (op_code == 2) {
            pkt.info = std::string(sender_ip) + " is at " + pkt.mac_src;
        } else {
            pkt.info = "Operacion ARP desconocida: " + std::to_string(op_code);
        }
    }
    else if (pkt.eth_type == 0x86DD) { // TRÁFICO IPv6 (Internet Protocol Version 6)
        pkt.protocol = "IPv6";
        const u_char* ipv6_hdr = packet + sizeof(struct ether_header);
        
        // Siguiente cabecera (Next Header) determina si es ICMPv6, TCP o UDP
        uint8_t next_header = ipv6_hdr[6]; 
        
        // Extracción de direcciones IPv6 crudas mapeadas a texto estructurado
        char src_ipv6[40];
        char dst_ipv6[40];
        inet_ntop(AF_INET6, (ipv6_hdr + 8), src_ipv6, sizeof(src_ipv6));
        inet_ntop(AF_INET6, (ipv6_hdr + 24), dst_ipv6, sizeof(dst_ipv6));
        
        pkt.source_ip = src_ipv6;
        pkt.dest_ip = dst_ipv6;
        pkt.src_port = 0; pkt.dst_port = 0;
        
        if (next_header == 58) { // 58 es el identificador nativo para ICMPv6
            pkt.protocol = "ICMPv6";
            const u_char* icmp6_hdr = packet + sizeof(struct ether_header) + 40; // 40 bytes fijos de IPv6
            uint8_t type = icmp6_hdr[0];
            
            if (type == 133) pkt.info = "Router Solicitation";
            else if (type == 134) pkt.info = "Router Advertisement";
            else if (type == 135) pkt.info = "Neighbor Solicitation";
            else if (type == 136) pkt.info = "Neighbor Advertisement";
            else pkt.info = "Tipo ICMPv6: " + std::to_string(type);
        } else {
            pkt.info = "Procesado sobre tunel IPv6 (Next Header: " + std::to_string(next_header) + ")";
        }
    }
    else { // Cualquier otra trama fuera del espectro estándar TCP/IP básico
        pkt.protocol = "No-IP";
        char eth_hex[16];
        snprintf(eth_hex, sizeof(eth_hex), "0x%04X", pkt.eth_type);
        pkt.source_ip = "Capa Enlace";
        pkt.dest_ip = "Capa Enlace";
        pkt.info = "Tipo de trama Ethernet no controlado: " + std::string(eth_hex);
    }

    // Insertar el paquete de manera segura usando Mutex
    std::lock_guard<std::mutex> lock(g_packets_mutex);
    g_packets.push_back(pkt);
}

// Función principal del hilo en segundo plano
void HiloCapturaEjecucion(std::string interfaz) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Abrir interfaz en modo promiscuo, con un buffer de tiempo límite de 100ms
    pcap_handle = pcap_open_live(interfaz.c_str(), BUFSIZ, 1, 100, errbuf);
    if (pcap_handle == nullptr) {
        std::cerr << "Error abriendo dispositivo: " << errbuf << std::endl;
        g_is_capturing = false;
        return;
    }

    // Escucha infinita controlada de paquetes
    pcap_loop(pcap_handle, 0, PacketCallback, nullptr);
    pcap_close(pcap_handle);
}

bool IniciarHiloCaptura(const std::string& interfaz) {
    if (g_is_capturing) return false;
    if (interfaz.empty()) return false;

    g_is_capturing = true;
    capture_thread = std::thread(HiloCapturaEjecucion, interfaz);
    return true;
}

void DetenerCaptura() {
    if (!g_is_capturing) return;
    g_is_capturing = false;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle); // Rompe el bloqueo de pcap_loop de manera segura
    }
    if (capture_thread.joinable()) {
        capture_thread.join();
    }
}