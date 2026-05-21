// Librerías de Allegro
#include <allegro5/allegro.h>
#include <allegro5/allegro_primitives.h>
#include <allegro5/allegro_font.h>
#include <allegro5/allegro_ttf.h>

// Librerías de Libpcap
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>

// Librerías de C/C++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>

#define RESOL_X 1280
#define RESOL_Y 720
#define AL_COLOR(c) al_map_rgb(c, c, c)

//using namespace std;

int link_hdr_length = 0;

// Estructura para el vector
struct DatosPaquete {
    int id;
    std::string src_ip;
    std::string dst_ip;
    std::string protocolo;
    int tos;
    int ttl;
    int len;
    int hlen;
};

struct ALLEGRO_UTIL {
    ALLEGRO_FONT* fuente;

    ALLEGRO_UTIL() {
        fuente = nullptr;
    }
};

enum BARRA_IDENT { NUM, ORIGEN, DESTINO, PROTOCOLO, TIEMPO, INFO, BARRA_IDENT_TAM };

inline void iniciar_recursos(ALLEGRO_UTIL& recursos);
inline void descargar_recursos(ALLEGRO_UTIL& recursos);

// Función para hacer texto los id 
std::string obtener_protocolo(uint8_t prot_id) {
    switch (prot_id) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        default:
            return "Otro (" + std::to_string(prot_id) + ")";
    }
}

void dibujado_pantalla(ALLEGRO_UTIL& recursos) {
    const float ESPACIADO_TXT{ 30 };
    ALLEGRO_COLOR color_barra_ident(al_map_rgb(170, 190, 240));
    al_clear_to_color(al_map_rgb(255, 255, 255));

    //----- Líneas diseño pantalla (arriba a abajo) -----//
    al_draw_filled_rectangle(0, 40, RESOL_X, 43, AL_COLOR(128));
    al_draw_filled_rectangle(0, 100, RESOL_X, 103, AL_COLOR(128));
    al_draw_filled_rectangle(15, 115, RESOL_X - 15, 160, AL_COLOR(128));        //Barra búsqueda

    al_draw_rectangle(15, 170, RESOL_X - 15, 530, AL_COLOR(128), 3);                        //Sniffeador
    //barra entera
    al_draw_filled_rectangle(20, 175, RESOL_X - 20, 210, color_barra_ident);
    for (int i{ 1 }; i <= BARRA_IDENT_TAM; i++) {
        float division = i * float(RESOL_X - 40) / BARRA_IDENT_TAM;
        float division_txt = (i - 1) * float(RESOL_X - 40) / BARRA_IDENT_TAM;
        al_draw_filled_rectangle(20 + division, 175, 23 + division, 210, AL_COLOR(255));

        switch(i - 1) {
        case NUM:       al_draw_text(recursos.fuente, AL_COLOR(0), ESPACIADO_TXT + division_txt, 180, 0, "No.");       break;
        case ORIGEN:    al_draw_text(recursos.fuente, AL_COLOR(0), ESPACIADO_TXT + division_txt, 180, 0, "Origen");       break;
        case DESTINO:   al_draw_text(recursos.fuente, AL_COLOR(0), ESPACIADO_TXT + division_txt, 180, 0, "Destino");       break;
        case PROTOCOLO: al_draw_text(recursos.fuente, AL_COLOR(0), ESPACIADO_TXT + division_txt, 180, 0, "Protocolo");       break;
        case TIEMPO:    al_draw_text(recursos.fuente, AL_COLOR(0), ESPACIADO_TXT + division_txt, 180, 0, "Tiempo");       break;
        case INFO:      al_draw_text(recursos.fuente, AL_COLOR(0), ESPACIADO_TXT + division_txt, 180, 0, "Info");       break;
        }
    }
    
    //Debe existir una lista aquí para mostrar los datos
    /*
    for (int i{}; i < 1989; i++) {
        // Está siendo escrita en terminal, no sé si querías que sólo hiciera el vector o lo imprimiera a pantalla con allegro
        // Checa la línea 132
    }

    al_draw_rectangle(15, 540, RESOL_X / 2 - 5, RESOL_Y - 15, AL_COLOR(128), 3);            //campo 2
    al_draw_rectangle(RESOL_X / 2 + 5, 540, RESOL_X - 15, RESOL_Y - 15, AL_COLOR(128), 3);  //Campo 3
    */

    //----- Botones inter -----//
    al_draw_filled_circle(35, 70, 20, al_map_rgb(60, 100, 230));
    al_draw_filled_circle(85, 70, 20, al_map_rgb(240, 40, 120));
    al_draw_filled_circle(135, 70, 20, al_map_rgb(20, 230, 130));
    al_draw_circle(185, 70, 17.5, AL_COLOR(192), 5);       //Lupa

    //Barra búsqueda/ filtro /idk
    al_draw_circle(40, 137.5, 15, AL_COLOR(192), 5);       //Lupa

    al_flip_display();
}

// Cambiado para que ahora reciba el vector y almacene los datos en memoria
void call_me(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packetd_ptr) {
    // Convertir el puntero user de vuelta a tipo std::vector
    std::vector<DatosPaquete>* lista_paquetes = (std::vector<DatosPaquete>*)user;

    packetd_ptr += link_hdr_length;
    struct ip* ip_hdr = (struct ip*)packetd_ptr;

    DatosPaquete p;
    p.src_ip = inet_ntoa(ip_hdr->ip_src);
    p.dst_ip = inet_ntoa(ip_hdr->ip_dst);
    p.id = ntohs(ip_hdr->ip_id);
    p.ttl = ip_hdr->ip_ttl;
    p.tos = ip_hdr->ip_tos;
    p.len = ntohs(ip_hdr->ip_len);
    p.hlen = ip_hdr->ip_hl;
    p.protocolo = obtener_protocolo(ip_hdr->ip_p); // Captutar el protocolo

    // Imprimir en consola
    printf("ID: %d | SRC: %s | DST: %s | PROTO: %s | TTL: %d\n", 
           p.id, p.src_ip.c_str(), p.dst_ip.c_str(), p.protocolo.c_str(), p.ttl);

    // Guardar en el vector
    if (lista_paquetes != nullptr) {
        lista_paquetes->push_back(p);
    }
}

int main(int argc, char const* argv[]) {
    // Inicialización de Allegro y complementos
    if (!al_init() || !al_init_primitives_addon() || !al_init_font_addon() || !al_init_ttf_addon()) {
        printf("ERR: No se pudo inicializar Allegro\n");
        return -1;
    }
    
    // Instalar teclado
    al_install_keyboard();

    ALLEGRO_DISPLAY* display = al_create_display(RESOL_X, RESOL_Y);
    if (!display) {
        printf("ERR: No se pudo crear el display de Allegro\n");
        return -1;
    }

    // Variables de lógica
    ALLEGRO_EVENT_QUEUE* cola_eventos = al_create_event_queue();
    ALLEGRO_TIMER* tiempo = al_create_timer(1.0 / 60); // 60 FPS
    ALLEGRO_EVENT eventos;
    ALLEGRO_UTIL recursos;
    
    bool programa_corriendo = true;
    bool capturando = true; // Variable de control para pausar con 'P'
    std::vector<DatosPaquete> vector_paquetes; // Almacenar la captura

    al_set_window_title(display, "Packet Sniffeador");

    al_register_event_source(cola_eventos, al_get_timer_event_source(tiempo));
    al_register_event_source(cola_eventos, al_get_display_event_source(display));
    al_register_event_source(cola_eventos, al_get_keyboard_event_source());

    iniciar_recursos(recursos);

    // CONFIGURACIÓN DE PCAP (lo moví, antes estaba después del bucle de la pantalla)
    const char* device = "enp0s3";
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    pcap_t* capdev = pcap_open_live(device, BUFSIZ, 1, 10, error_buffer);
    if (capdev == NULL) {
        printf("ERR: pcap_open_live() %s\n", error_buffer);
        al_destroy_display(display);
        exit(1);
    }

    // Configurar pcap como no bloqueante para que no se congele la interfaz
    pcap_setnonblock(capdev, 1, error_buffer);

    int link_hdr_type = pcap_datalink(capdev);
    switch (link_hdr_type) {
        case DLT_NULL:   link_hdr_length = 4;  break;
        case DLT_EN10MB: link_hdr_length = 14; break;
        default:         link_hdr_length = 0;
    }

    // Mensaje chispa de cómo funciona
    printf("Iniciando captura... Presiona 'P' para pausar o 'X' para salir y guardar.\n");
    al_start_timer(tiempo);

    // Bucle con captura e interfaz
    while (programa_corriendo) {
        al_wait_for_event(cola_eventos, &eventos);

        switch (eventos.type) {
        case ALLEGRO_EVENT_TIMER:
            // Cada 1/60 de segundo revisa si hay paquetes disponibles
            if (capturando) {
                // pcap_dispatch procesa todos los paquetes en cola en ese momento sin bloquear
                pcap_dispatch(capdev, -1, call_me, (u_char*)&vector_paquetes);
            }
            dibujado_pantalla(recursos);
            break;

        case ALLEGRO_EVENT_KEY_DOWN:
            if (eventos.keyboard.keycode == ALLEGRO_KEY_P) {
                capturando = !capturando; // Alternar estado
                printf(capturando ? "\n=== CAPTURA REANUDADA ===\n" : "\n=== CAPTURA PAUSADA ===\n");
            }
            else if (eventos.keyboard.keycode == ALLEGRO_KEY_X) {
                programa_corriendo = false; // Rompe el bucle para guardar y salir
            }
            break;

        case ALLEGRO_EVENT_DISPLAY_CLOSE:
            programa_corriendo = false;
            break;
        }
    }

    // GUARDADO DE ARCHIVOS (.csv) e INDICA CUÁNTOS SE CAPTURARON/GUARDARON
    printf("\nGuardando %zu paquetes en el archivo...\n", vector_paquetes.size());
    FILE* csv_file = fopen("paquetes_capturados.csv", "w");
    if (csv_file != NULL) {
        fprintf(csv_file, "ID,SRC_IP,DST_IP,PROTOCOLO,TOS,TTL,LEN,HLEN\n");
        
        // Del vector al archivo
        for (const auto& pq : vector_paquetes) {
            fprintf(csv_file, "%d,%s,%s,%s,0x%x,%d,%d,%d\n",
                pq.id, pq.src_ip.c_str(), pq.dst_ip.c_str(), pq.protocolo.c_str(),
                pq.tos, pq.ttl, pq.len, pq.hlen);
        }
        fclose(csv_file);
        printf("FINALIZADO... GUARDADO EXITOSAMENTE EN 'paquetes_capturados.csv'\n");
    } else {
        printf("ERR: No se pudo crear el archivo CSV\n");
    }

    // Cerrar todo (no supe si ponerlo en tu función de iniciar/descargar)
    pcap_close(capdev);
    al_destroy_display(display);
    al_destroy_timer(tiempo);
    descargar_recursos(recursos);

    return 0;
}

inline void iniciar_recursos(ALLEGRO_UTIL& recursos) {
    recursos.fuente = al_load_ttf_font("fonts/Garet-Book.ttf", 20, 0);
}

inline void descargar_recursos(ALLEGRO_UTIL& recursos) {
    if(recursos.fuente != nullptr) {
        al_destroy_font(recursos.fuente);
    }
}
