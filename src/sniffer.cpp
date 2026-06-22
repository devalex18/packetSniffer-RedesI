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

// Punto cero de tiempo: se fija con el primer paquete de cada sesión
struct timeval g_capture_start_time = { -1, 0 };

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


// Detecta el protocolo de aplicación a partir del puerto origen o destino.
// Devuelve el nombre del protocolo si es conocido, o "" si no lo es.
static std::string ProtocoloPorPuerto(uint16_t src, uint16_t dst) {
    // Se revisan ambos puertos; el menor suele ser el "bien conocido"
    for (uint16_t p : {dst, src}) {
        switch (p) {
            // Acceso remoto 
            case 22:   return "SSH";
            case 23:   return "Telnet";
            case 3389: return "RDP";
            case 5900: return "VNC";
            // Web
            case 80:   return "HTTP";
            case 443:  return "HTTPS";
            case 8080: return "HTTP-Alt";
            case 8443: return "HTTPS-Alt";
            // Correo
            case 25:   return "SMTP";
            case 465:  return "SMTPS";
            case 587:  return "SMTP-Sub";
            case 110:  return "POP3";
            case 995:  return "POP3S";
            case 143:  return "IMAP";
            case 993:  return "IMAPS";
            // DNS / Nombres
            case 53:   return "DNS";
            case 5353: return "mDNS";
            case 137:  return "NetBIOS-NS";
            case 138:  return "NetBIOS-DG";
            case 139:  return "NetBIOS-SS";
            case 445:  return "SMB";
            // Transferencia de archivos
            case 20:   return "FTP-Data";
            case 21:   return "FTP";
            case 69:   return "TFTP";
            case 989:  return "FTPS-Data";
            case 990:  return "FTPS";
            // Gestión de red
            case 161:  return "SNMP";
            case 162:  return "SNMP-Trap";
            case 514:  return "Syslog";
            case 123:  return "NTP";
            case 67:   return "DHCP-Srv";
            case 68:   return "DHCP-Cli";
            case 546:  return "DHCPv6-Cli";
            case 547:  return "DHCPv6-Srv";
            // Bases de datos
            case 3306: return "MySQL";
            case 5432: return "PostgreSQL";
            case 1433: return "MSSQL";
            case 1521: return "Oracle";
            case 6379: return "Redis";
            case 27017:return "MongoDB";
            // Comunicaciones / Mensajería
            case 5060: return "SIP";
            case 5061: return "SIPS";
            case 1194: return "OpenVPN";
            case 500:  return "IKE";
            case 4500: return "IPSec-NAT";
            // Otros comunes
            case 179:  return "BGP";
            case 389:  return "LDAP";
            case 636:  return "LDAPS";
            case 88:   return "Kerberos";
            case 111:  return "RPC";
            case 2049: return "NFS";
            case 6881: return "BitTorrent";
            default:   break;
        }
    }
    return "";
}

// Callback obligatorio de libpcap que se ejecuta por cada paquete detectado
void PacketCallback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (!g_is_capturing) return;

    PacketData pkt;
    pkt.id = g_packet_id_counter++;
    pkt.length = pkthdr->len;

    // Captura con tiempo desde el primer paquete
    if (g_capture_start_time.tv_sec == -1) {
        g_capture_start_time = pkthdr->ts;
    }
    long delta_sec  = pkthdr->ts.tv_sec  - g_capture_start_time.tv_sec;
    long delta_usec = pkthdr->ts.tv_usec - g_capture_start_time.tv_usec;
    if (delta_usec < 0) {
        delta_sec  -= 1;
        delta_usec += 1000000;
    }
    char time_str[32];
    snprintf(time_str, sizeof(time_str), "%ld.%06ld", delta_sec, delta_usec);
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
        pkt.ip_ttl     = ip->ttl;
        pkt.ip_proto   = ip->protocol;
        pkt.ip_version = 4;
        pkt.ip_len     = ntohs(ip->tot_len);

        size_t ip_header_len = ip->ihl * 4;
        const u_char* payload = packet + sizeof(struct ether_header) + ip_header_len;

        // Decodificar Capa de Transporte / Protocolo sobre IPv4
        switch (ip->protocol) {
            case IPPROTO_TCP: {
                struct tcphdr* tcp = (struct tcphdr*)payload;
                pkt.src_port     = ntohs(tcp->source);
                pkt.dst_port     = ntohs(tcp->dest);
                pkt.protocol     = "TCP";
                pkt.app_protocol = ProtocoloPorPuerto(pkt.src_port, pkt.dst_port);
                // Flags TCP: bits bajos del byte de flags (offset 13 del header TCP)
                pkt.tcp_flags = (uint8_t)(tcp->th_flags & 0x3F);
                // Construir cadena de flags legible
                std::string flags_str;
                if (pkt.tcp_flags & 0x02) flags_str += "SYN ";
                if (pkt.tcp_flags & 0x10) flags_str += "ACK ";
                if (pkt.tcp_flags & 0x01) flags_str += "FIN ";
                if (pkt.tcp_flags & 0x04) flags_str += "RST ";
                if (pkt.tcp_flags & 0x08) flags_str += "PSH ";
                if (pkt.tcp_flags & 0x20) flags_str += "URG ";
                if (!flags_str.empty() && flags_str.back() == ' ') flags_str.pop_back();
                pkt.info = std::to_string(pkt.src_port) + " -> " + std::to_string(pkt.dst_port)
                         + " [" + flags_str + "]"
                         + (pkt.app_protocol.empty() ? "" : " " + pkt.app_protocol);
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr* udp = (struct udphdr*)payload;
                pkt.src_port     = ntohs(udp->source);
                pkt.dst_port     = ntohs(udp->dest);
                pkt.protocol     = "UDP";
                pkt.app_protocol = ProtocoloPorPuerto(pkt.src_port, pkt.dst_port);
                pkt.info = std::to_string(pkt.src_port) + " -> " + std::to_string(pkt.dst_port)
                         + (pkt.app_protocol.empty() ? "" : " " + pkt.app_protocol);
                break;
            }
            case IPPROTO_ICMP: {
                pkt.protocol = "ICMP";
                struct icmphdr* icmp = (struct icmphdr*)payload;
                pkt.src_port = 0; pkt.dst_port = 0;
                pkt.info = "Tipo ICMP: " + std::to_string(icmp->type) + " Codigo: " + std::to_string(icmp->code);
                break;
            }
            case 2: { // IGMP
                pkt.protocol = "IGMP";
                pkt.src_port = 0; pkt.dst_port = 0;
                uint8_t igmp_type = payload[0];
                switch (igmp_type) {
                    case 0x11: pkt.info = "Membership Query";       break;
                    case 0x16: pkt.info = "Membership Report v2";   break;
                    case 0x22: pkt.info = "Membership Report v3";   break;
                    case 0x17: pkt.info = "Leave Group";            break;
                    default:   pkt.info = "Tipo IGMP: 0x" + std::to_string(igmp_type); break;
                }
                break;
            }
            case 4: { // IP-in-IP tunnel
                pkt.protocol = "IPIP";
                pkt.src_port = 0; pkt.dst_port = 0;
                pkt.info = "Tunel IP-in-IP encapsulado";
                break;
            }
            case 47: { // GRE
                pkt.protocol = "GRE";
                pkt.src_port = 0; pkt.dst_port = 0;
                uint16_t gre_flags = ntohs(*(uint16_t*)payload);
                char flags_hex[8];
                snprintf(flags_hex, sizeof(flags_hex), "%04X", gre_flags);
                pkt.info = "Generic Routing Encapsulation (flags: 0x" + std::string(flags_hex) + ")";
                break;
            }
            case 50: { // ESP - IPSec
                pkt.protocol = "ESP";
                pkt.src_port = 0; pkt.dst_port = 0;
                uint32_t spi = ntohl(*(uint32_t*)payload);
                char spi_str[16]; snprintf(spi_str, sizeof(spi_str), "0x%08X", spi);
                pkt.info = "IPSec ESP - SPI: " + std::string(spi_str) + " (datos cifrados)";
                break;
            }
            case 51: { // AH - IPSec
                pkt.protocol = "AH";
                pkt.src_port = 0; pkt.dst_port = 0;
                uint32_t spi = ntohl(*(uint32_t*)(payload + 4));
                char spi_str[16]; snprintf(spi_str, sizeof(spi_str), "0x%08X", spi);
                pkt.info = "IPSec AH - SPI: " + std::string(spi_str);
                break;
            }
            case 88: { // EIGRP (Cisco)
                pkt.protocol = "EIGRP";
                pkt.src_port = 0; pkt.dst_port = 0;
                uint8_t opcode = payload[1];
                switch (opcode) {
                    case 1:  pkt.info = "EIGRP Update";  break;
                    case 3:  pkt.info = "EIGRP Query";   break;
                    case 4:  pkt.info = "EIGRP Reply";   break;
                    case 5:  pkt.info = "EIGRP Hello";   break;
                    default: pkt.info = "EIGRP Opcode: " + std::to_string(opcode); break;
                }
                break;
            }
            case 89: { // OSPF
                pkt.protocol = "OSPF";
                pkt.src_port = 0; pkt.dst_port = 0;
                uint8_t ospf_type = payload[1];
                switch (ospf_type) {
                    case 1:  pkt.info = "OSPF Hello";                          break;
                    case 2:  pkt.info = "OSPF Database Description (DBD)";     break;
                    case 3:  pkt.info = "OSPF Link State Request (LSR)";       break;
                    case 4:  pkt.info = "OSPF Link State Update (LSU)";        break;
                    case 5:  pkt.info = "OSPF Link State Ack (LSAck)";         break;
                    default: pkt.info = "OSPF Tipo: " + std::to_string(ospf_type); break;
                }
                break;
            }
            case 103: { // PIM
                pkt.protocol = "PIM";
                pkt.src_port = 0; pkt.dst_port = 0;
                uint8_t pim_type = payload[1] & 0x0F;
                switch (pim_type) {
                    case 0:  pkt.info = "PIM Hello";       break;
                    case 1:  pkt.info = "PIM Register";    break;
                    case 3:  pkt.info = "PIM Join/Prune";  break;
                    case 4:  pkt.info = "PIM Bootstrap";   break;
                    default: pkt.info = "PIM Tipo: " + std::to_string(pim_type); break;
                }
                break;
            }
            case 112: { // VRRP
                pkt.protocol = "VRRP";
                pkt.src_port = 0; pkt.dst_port = 0;
                uint8_t vrid = payload[1];
                uint8_t priority = payload[2];
                pkt.info = "VRRP Advertisement - VRID: " + std::to_string(vrid) + " Prioridad: " + std::to_string(priority);
                break;
            }
            case 115: { // L2TP
                pkt.protocol = "L2TP";
                pkt.src_port = 0; pkt.dst_port = 0;
                pkt.info = "Layer 2 Tunneling Protocol";
                break;
            }
            case 132: { // SCTP
                pkt.protocol = "SCTP";
                pkt.src_port = ntohs(*(uint16_t*)payload);
                pkt.dst_port = ntohs(*(uint16_t*)(payload + 2));
                pkt.info = "Puerto Origen: " + std::to_string(pkt.src_port) + " -> Puerto Destino: " + std::to_string(pkt.dst_port);
                break;
            }
            case 46: { // RSVP
                pkt.protocol = "RSVP";
                pkt.src_port = 0; pkt.dst_port = 0;
                uint8_t msg_type = payload[1];
                switch (msg_type) {
                    case 1:  pkt.info = "RSVP Path";     break;
                    case 2:  pkt.info = "RSVP Resv";     break;
                    case 3:  pkt.info = "RSVP PathErr";  break;
                    default: pkt.info = "RSVP Tipo: " + std::to_string(msg_type); break;
                }
                break;
            }
            case 41: { // IPv6 encapsulado en IPv4
                pkt.protocol = "IPv6";
                pkt.src_port = 0; pkt.dst_port = 0;
                pkt.info = "IPv6 encapsulado en IPv4 (6in4 tunnel)";
                break;
            }
            case 8:   pkt.protocol = "EGP";     pkt.src_port = 0; pkt.dst_port = 0; pkt.info = "EGP (proto 8)";     break;
            case 9:   pkt.protocol = "IGRP";    pkt.src_port = 0; pkt.dst_port = 0; pkt.info = "IGRP (proto 9)";    break;
            case 58:  pkt.protocol = "ICMPv6";  pkt.src_port = 0; pkt.dst_port = 0; pkt.info = "ICMPv6 (proto 58)"; break;
            case 97:  pkt.protocol = "ETHERIP"; pkt.src_port = 0; pkt.dst_port = 0; pkt.info = "ETHERIP (proto 97)"; break;
            case 108: pkt.protocol = "IPComp";  pkt.src_port = 0; pkt.dst_port = 0; pkt.info = "IPComp (proto 108)"; break;
            case 137: pkt.protocol = "MPLS";    pkt.src_port = 0; pkt.dst_port = 0; pkt.info = "MPLS (proto 137)";  break;
            case 139: pkt.protocol = "HIP";     pkt.src_port = 0; pkt.dst_port = 0; pkt.info = "HIP (proto 139)";   break;
            default: {
                // Protocolo IP no reconocido: se conserva el número crudo
                pkt.src_port = 0; pkt.dst_port = 0;
                pkt.protocol = "IPv4/" + std::to_string(ip->protocol);
                pkt.info = "Protocolo IPv4 no decodificado: " + std::to_string(ip->protocol);
                break;
            }
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
    else if (pkt.eth_type == 0x86DD) { // TRÁFICO IPv6
        pkt.protocol = "IPv6";
        const u_char* ipv6_hdr = packet + sizeof(struct ether_header);
        pkt.ip_version = 6;
        pkt.ip_len = ntohs(*(uint16_t*)(ipv6_hdr + 4)) + 40; // Payload length + 40 bytes fixed header
        
        // Siguiente cabecera determina si es ICMPv6, TCP o UDP
        uint8_t next_header = ipv6_hdr[6]; 
        
        // Extracción de direcciones IPv6 crudas mapeadas a texto estructurado
        char src_ipv6[40];
        char dst_ipv6[40];
        inet_ntop(AF_INET6, (ipv6_hdr + 8), src_ipv6, sizeof(src_ipv6));
        inet_ntop(AF_INET6, (ipv6_hdr + 24), dst_ipv6, sizeof(dst_ipv6));
        
        pkt.source_ip = src_ipv6;
        pkt.dest_ip = dst_ipv6;
        pkt.src_port = 0; pkt.dst_port = 0;
        
        if (next_header == 58) { // 58 es el identificador para ICMPv6
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

    pcap_loop(pcap_handle, 0, PacketCallback, nullptr);
    pcap_close(pcap_handle);
}

bool IniciarHiloCaptura(const std::string& interfaz) {
    if (g_is_capturing) return false;
    if (interfaz.empty()) return false;

    // Resetear el punto cero para que el primer paquete de esta sesión sea t=0
    g_capture_start_time = { -1, 0 };

    g_is_capturing = true;
    capture_thread = std::thread(HiloCapturaEjecucion, interfaz);
    return true;
}

void DetenerCaptura() {
    if (!g_is_capturing) return;
    g_is_capturing = false;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
    }
    if (capture_thread.joinable()) {
        capture_thread.join();
    }
}