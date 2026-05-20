#include <iostream>
#include <allegro5/allegro.h>

#include <allegro5/allegro_image.h>
#include <allegro5/allegro_font.h>
#include <allegro5/allegro_ttf.h>
#include <allegro5/allegro_primitives.h>

using namespace std;

int main() {
    //Inicializar Allegro 5
	if (!al_init())						return -1;
	if (!al_init_image_addon())			return -1;
	if (!al_init_primitives_addon())	return -1;
	if (!al_install_keyboard())			return -1;
	if (!al_install_mouse())			return -1;
    
	ALLEGRO_EVENT_QUEUE* cola_eventos = al_create_event_queue();
	ALLEGRO_EVENT_QUEUE* cola_pantalla = al_create_event_queue();
	ALLEGRO_TIMER* tiempo = al_create_timer(1.0 / 60);
	ALLEGRO_EVENT eventos;
	Pantalla pant(null, "Packet Sniffer");
    bool programa_corriendo = true, bucle = true;
    
	al_register_event_source(cola_eventos, al_get_keyboard_event_source());
	al_register_event_source(cola_eventos, al_get_mouse_event_source());
	al_register_event_source(cola_eventos, al_get_timer_event_source(tiempo));
	al_register_event_source(cola_pantalla, al_get_display_event_source((ALLEGRO_DISPLAY*)pant.get_display()));

    //Lógica del programa
    while (programa_corriendo) {
        printf("Sniffeando\n");
        programa_corriendo = false;
    }

    return 0;
}
