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

#define RESOL_X 1280
#define RESOL_Y 720
#define AL_COLOR(c) al_map_rgb(c, c, c)

int link_hdr_length = 0;

struct ALLEGRO_UTIL {
    ALLEGRO_FONT* fuente;

    ALLEGRO_UTIL() {
        fuente = nullptr;
    }
};

enum BARRA_IDENT { NUM, ORIGEN, DESTINO, PROTOCOLO, TIEMPO, INFO, BARRA_IDENT_TAM };

inline void iniciar_recursos(ALLEGRO_UTIL& recursos);
inline void descargar_recursos(ALLEGRO_UTIL& recursos);

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
        case TIEMPO:       al_draw_text(recursos.fuente, AL_COLOR(0), ESPACIADO_TXT + division_txt, 180, 0, "Tiempo");       break;
        case INFO:       al_draw_text(recursos.fuente, AL_COLOR(0), ESPACIADO_TXT + division_txt, 180, 0, "Info");       break;
        }
    }
    //Debe existir una lista aquí para mostrar los datos
    for (int i{}; i < 1989; i++) {

    }

    al_draw_rectangle(15, 540, RESOL_X / 2 - 5, RESOL_Y - 15, AL_COLOR(128), 3);            //campo 2
    al_draw_rectangle(RESOL_X / 2 + 5, 540, RESOL_X - 15, RESOL_Y - 15, AL_COLOR(128), 3);  //Campo 3

    //----- Botones inter -----//
    al_draw_filled_circle(35, 70, 20, al_map_rgb(60, 100, 230));
    al_draw_filled_circle(85, 70, 20, al_map_rgb(240, 40, 120));
    al_draw_filled_circle(135, 70, 20, al_map_rgb(20, 230, 130));
    al_draw_circle(185, 70, 17.5, AL_COLOR(192), 5);       //Lupa

    //Barra búsqueda/ filtro /idk
    al_draw_circle(40, 137.5, 15, AL_COLOR(192), 5);       //Lupa

    al_flip_display();
}

// Modifiqué la función para recibir el archivo .csv en el puntero user
void call_me(u_char* user, const struct pcap_pkthdr* pkthdr,
    const u_char* packetd_ptr) {

    // Convertirr el puntero user de vuelta a tipo FILE*
    FILE* csv_file = (FILE*)user;

    packetd_ptr += link_hdr_length;
    struct ip* ip_hdr = (struct ip*)packetd_ptr;

    char packet_srcip[INET_ADDRSTRLEN];
    char packet_dstip[INET_ADDRSTRLEN];
    strcpy(packet_srcip, inet_ntoa(ip_hdr->ip_src));
    strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst));

    int packet_id = ntohs(ip_hdr->ip_id),
        packet_ttl = ip_hdr->ip_ttl,
        packet_tos = ip_hdr->ip_tos,
        packet_len = ntohs(ip_hdr->ip_len),
        packet_hlen = ip_hdr->ip_hl;

    // Estructura igual a la de juanikilador
    printf("************************************"
        "**************************************\n");
    printf("ID: %d | SRC: %s | DST: %s | TOS: 0x%x | TTL: %d\n", packet_id,
        packet_srcip, packet_dstip, packet_tos, packet_ttl);

    // Guardamos los datos (solo si el puntero es valido)
    if (csv_file != NULL) {
        fprintf(csv_file, "%d,%s,%s,0x%x,%d,%d,%d\n",
            packet_id, packet_srcip, packet_dstip, packet_tos, packet_ttl, packet_len, packet_hlen);
        // fflush para guardar
        fflush(csv_file);
    }
}

int main(int argc, char const* argv[]) {
    // Inicialización de Allegro
    if (!al_init() ||
        !al_init_primitives_addon() ||
        !al_init_font_addon() ||
        !al_init_ttf_addon()) {
        printf("ERR: No se pudo inicializar Allegro\n");
        return -1;
    }

    // Creación de la ventana (display)
    ALLEGRO_DISPLAY* display = al_create_display(RESOL_X, RESOL_Y);
    if (!display) {
        printf("ERR: No se pudo crear el display de Allegro\n");
        return -1;
    }

    //Variables allegro
    ALLEGRO_EVENT_QUEUE* cola_eventos = al_create_event_queue();
    ALLEGRO_TIMER* tiempo = al_create_timer(1.0 / 60);
    ALLEGRO_EVENT eventos;
    ALLEGRO_UTIL recursos;
    bool programa_corriendo = true;

    // Abrir y preparar el .csv
    FILE* csv_file = fopen("paquetes_capturados.csv", "w");
    if (csv_file == NULL) {
        printf("ERR: No se pudo crear el archivo CSV\n");
        al_destroy_display(display);
        return -1;
    }
    // Estructura: ID,SRC,DST,TOS,TTL,LEN,HLEN
    fprintf(csv_file, "ID,SRC_IP,DST_IP,TOS,TTL,LEN,HLEN\n");

    al_set_window_title(display, "Packet Sniffeador");

    al_register_event_source(cola_eventos, al_get_timer_event_source(tiempo));
    al_register_event_source(cola_eventos, al_get_display_event_source(display));

    iniciar_recursos(recursos);

    al_start_timer(tiempo);
    while (programa_corriendo) {
        al_wait_for_event(cola_eventos, &eventos);

        switch (eventos.type) {
            //Dibujado de la pantalla
        case ALLEGRO_EVENT_TIMER:
            dibujado_pantalla(recursos);
            break;
        case ALLEGRO_EVENT_DISPLAY_CLOSE:
            programa_corriendo = false;
            break;
        }

    }

    const char* device = "enp0s3";
    char error_buffer[PCAP_ERRBUF_SIZE];
    int packets_count = 5;

    pcap_t* capdev = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);

    if (capdev == NULL) {
        printf("ERR: pcap_open_live() %s\n", error_buffer);
        fclose(csv_file); // Cerrar .csv
        al_destroy_display(display);
        exit(1);
    }

    int link_hdr_type = pcap_datalink(capdev);

    switch (link_hdr_type) {
    case DLT_NULL:
        link_hdr_length = 4;
        break;
    case DLT_EN10MB:
        link_hdr_length = 14;
        break;
    default:
        link_hdr_length = 0;
    }

    // Cerrar todo
    fclose(csv_file);
    al_destroy_display(display);
    al_destroy_timer(tiempo);
    descargar_recursos(recursos);

    // Pasar .csv como ultimo parametro
    if (pcap_loop(capdev, packets_count, call_me, (u_char*)csv_file)) {
        printf("ERR: pcap_loop() failed!\n");
        fclose(csv_file); // Cerramos el archivo antes de salir
        exit(1);
    }

    // Mensaje de que todo ok
    printf("\nFINALIZADO... GUARDADO EN '.csv'\n");

    return 0;
}

inline void iniciar_recursos(ALLEGRO_UTIL& recursos) {
    recursos.fuente = al_load_ttf_font("fonts/Garet-Book.ttf", 20, 0);
}

inline void descargar_recursos(ALLEGRO_UTIL& recursos) {
    al_destroy_font(recursos.fuente);
}
