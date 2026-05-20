// Librerías de Allegro
#include <allegro5/allegro.h>

// Librerías de Libpcap
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>

// Librerías de C/C++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int link_hdr_length = 0;

// Modifiqué la función para recibir el archivo .csv en el puntero user
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr,
             const u_char *packetd_ptr) {
  
  // Convertirr el puntero user de vuelta a tipo FILE*
  FILE *csv_file = (FILE *)user;

  packetd_ptr += link_hdr_length;
  struct ip *ip_hdr = (struct ip *)packetd_ptr;
 
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

int main(int argc, char const *argv[]) {
  // Inicialización de Allegro
  if (!al_init()) {
    printf("ERR: No se pudo inicializar Allegro\n");
    return -1;
  }

  // Creación de la ventana (display)
  ALLEGRO_DISPLAY *display = al_create_display(640, 480);
  if (!display) {
    printf("ERR: No se pudo crear el display de Allegro\n");
    return -1;
  }

  // Color de fondo
  al_clear_to_color(al_map_rgb(0, 0, 0));
  al_flip_display();

  // Abrir y preparar el .csv
  FILE *csv_file = fopen("paquetes_capturados.csv", "w");
  if (csv_file == NULL) {
    printf("ERR: No se pudo crear el archivo CSV\n");
    al_destroy_display(display);
    return -1;
  }
  // Estructura: ID,SRC,DST,TOS,TTL,LEN,HLEN
  fprintf(csv_file, "ID,SRC_IP,DST_IP,TOS,TTL,LEN,HLEN\n");

  const char *device = "enp0s3";
  char error_buffer[PCAP_ERRBUF_SIZE];
  int packets_count = 5;

  pcap_t *capdev = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);

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

  // Pasar .csv como ultimo parametro
  if (pcap_loop(capdev, packets_count, call_me, (u_char *)csv_file)) {
    printf("ERR: pcap_loop() failed!\n");
    fclose(csv_file); // Cerramos el archivo antes de salir
    al_destroy_display(display);
    exit(1);
  }

  // Cerrar todo
  fclose(csv_file);
  al_destroy_display(display);

  // Mensaje de que todo ok
  printf("\nFINALIZADO... GUARDADO EN '.csv'\n");
  return 0;
}
