#pragma once
/*-------- LIBRERÍAS DE C++ --------*/
#include <iostream>

/*----- LIBRERÍAS DE ALLEGRO 5 -----*/
#include <allegro5/allegro5.h>
#include <allegro5/allegro_image.h>

/*----- MACROS --------------------------------------------------------*/
#define RESOL_X 1920
#define RESOL_Y 1080
#define TIEMPO_ESC 60

#define IMAGEN	ALLEGRO_BITMAP*
#define DISPLAY	ALLEGRO_DISPLAY*
#define al_draw_bitmap_all(IM, sx, sy, sw, sh, COLOR, cx, cy, dx, dy, xsca, ysca, angle, flag) al_draw_tinted_scaled_rotated_bitmap_region(IM, sx, sy, sw, sh, COLOR, cx, cy, dx, dy, xsca, ysca, angle, flag)

#define NORM_C(c) al_map_rgb(c, c, c)
#define TRANS_C(t) al_map_rgba(t, t, t, t)

//N = OSCURIDAD	CHAR / T = TRANSPARENCIA FLOAT
#define OSC_C(n,t) al_map_rgba(n * t, n * t, n * t, 255 * t)

#define DIR_S 1
#define RATIO_16_9 1.777777777777

using namespace std;

enum BOTONES_MOUSE { CLICK_IZQ, CLICK_DER, MAX_BOTON };
enum TIPO_CONTROL { TIPO_CONTROL_PLAY = 2 };

ALLEGRO_COLOR color_oscuro(ALLEGRO_COLOR, float);
ALLEGRO_COLOR operator*(ALLEGRO_COLOR, ALLEGRO_COLOR);
ALLEGRO_COLOR operator*(ALLEGRO_COLOR, float);
inline bool es_oscuro(ALLEGRO_COLOR);

class Pantalla {
private:
	bool pantalla_completa;
	short resol_x, resol_y, offset_x, offset_y;
	float tam_pant_x, tam_pant_y, ratio;
	void* display;
	IMAGEN al_buffer;
	IMAGEN al_buffer_real;

public:
	Pantalla(void*& icono, const char* nombre) {
		pantalla_completa = false;
		resol_x = RESOL_X;
		resol_y = RESOL_Y;
		offset_y = offset_x = 0;

		cambiar_pantalla_ventana();

		al_set_new_display_flags(ALLEGRO_RESIZABLE);
		display = al_create_display(resol_x, resol_y);

		//Filtro linear para evitar dientes en los sprites
		//al_set_new_bitmap_flags(ALLEGRO_MIN_LINEAR | ALLEGRO_MAG_LINEAR);
		al_buffer_real = al_create_bitmap(RESOL_X, RESOL_Y);
		al_buffer = al_create_sub_bitmap(al_buffer_real, 0, 0, RESOL_X, RESOL_Y);

		al_hide_mouse_cursor((DISPLAY)display);
		al_set_window_title((DISPLAY)display, nombre);
		al_set_display_icon((DISPLAY)display, (IMAGEN)icono);
	}
	~Pantalla() {
		al_destroy_display((DISPLAY)display);
		al_destroy_bitmap(al_buffer_real);
		al_destroy_bitmap(al_buffer);
	}

	inline IMAGEN buffer() {
		return al_buffer;
	}

	inline IMAGEN buffer_real() {
		return al_buffer_real;
	}

	inline const Coord off() {
		return Coord(offset_x, offset_y);
	}

	inline const Coord resol() {
		return Coord(RESOL_X + offset_x * 2, RESOL_Y + offset_y * 2);
	}

	inline void* get_display() {
		return display;
	}

	void cambiar_pantalla_ventana() {
		ALLEGRO_MONITOR_INFO resol_pant;
		al_get_monitor_info(0, &resol_pant);

		resol_x = resol_pant.x2 - resol_pant.x1;
		resol_y = resol_x / (16.0 / 9);

		resol_x *= .6;
		resol_y *= .6;

		offset_x = 0;
		offset_y = 0;

		tam_pant_x = float(resol_x) / RESOL_X;
		tam_pant_y = float(resol_y) / RESOL_Y;

		actualizar_buffer();
		al_set_display_flag((DISPLAY)display, ALLEGRO_FULLSCREEN_WINDOW, pantalla_completa);
	}

	void cambiar_resolucion_pantalla() {
		ALLEGRO_MONITOR_INFO resol_pant;
		al_get_monitor_info(0, &resol_pant);

		resol_x = resol_pant.x2 - resol_pant.x1;
		resol_y = resol_x / (16.0 / 9);

		tam_pant_x = float(resol_x) / RESOL_X;
		tam_pant_y = float(resol_y) / RESOL_Y;

		offset_y = (resol_pant.y2 - resol_pant.y1 - resol_y) / 2;

		actualizar_buffer();
	}

	void cambiar_pantalla_completa() {
		ALLEGRO_MONITOR_INFO resol_pant;
		pantalla_completa = !pantalla_completa;
		if (pantalla_completa) {
			cambiar_resolucion_pantalla();
		}
		else {
			cambiar_pantalla_ventana();
		}
		al_set_display_flag((DISPLAY)display, ALLEGRO_FULLSCREEN_WINDOW, pantalla_completa);
	}

	void actualizar_buffer() {
		ALLEGRO_MONITOR_INFO resol_pant;
		float ratio;

		al_get_monitor_info(0, &resol_pant);
		al_destroy_bitmap(al_buffer_real);
		al_destroy_bitmap(al_buffer);

		ratio = float(resol_pant.x2 - resol_pant.x1) / (resol_pant.y2 - resol_pant.y1);
		if (ratio > 1.0) {
			ratio = pow(ratio, -1);
			al_buffer_real = al_create_bitmap(RESOL_X, RESOL_X * ratio);
		}
		else {
			al_buffer_real = al_create_bitmap(RESOL_Y * ratio, RESOL_Y);
		}

		al_buffer = al_create_sub_bitmap(al_buffer_real, offset_x, offset_y, RESOL_X, RESOL_Y);
	}

	void dibujar(ALLEGRO_COLOR color = { 1.0, 1.0, 1.0, 1.0 }) {
		const float TAM_DIST{ 5 };

		//DIBUJAR AL DISPLAY
		al_set_target_backbuffer((DISPLAY)display);
		al_clear_to_color(NORM_C(0));

		al_draw_tinted_scaled_rotated_bitmap_region(al_buffer_real, 0, 0, resol().x, resol().y, color, 0, 0, 0, 0, tam_pant_x, tam_pant_y, 0, 0);
		al_flip_display();

		//LIMPIAR BUFFER
		al_set_target_bitmap(al_buffer);
		al_clear_to_color(TRANS_C(0));
	}

	//Dibujar con zoom
	void dibujar(float zoom, float dx, float dy, ALLEGRO_COLOR color = { 1.0, 1.0, 1.0, 1.0 }) {
		//DIBUJAR AL DISPLAY
		al_set_target_backbuffer((DISPLAY)display);
		al_clear_to_color(NORM_C(0));

		al_draw_tinted_scaled_rotated_bitmap_region(
			al_buffer_real, 0, 0, resol().x, resol().y, color, 0, 0,
			(-offset_x / 2 - dx) * tam_pant_x, (-offset_y / 2 - dy) * tam_pant_y,
			tam_pant_x * zoom, tam_pant_y * zoom, 0, 0);

		al_flip_display();

		//LIMPIAR BUFFER
		al_set_target_bitmap((IMAGEN)al_buffer);
		al_clear_to_color(NORM_C(0));
	}

	inline void estado_cursor(bool mostrar) {
		if (mostrar) {
			al_show_mouse_cursor((ALLEGRO_DISPLAY*)display);
		}
		else {
			al_hide_mouse_cursor((ALLEGRO_DISPLAY*)display);
		}
	}

	friend class Mouse;
};

class Mouse {
private:
	Coord pos;

public:
	bool presionado[MAX_BOTON];
	OPCION sobre_opc;

	Mouse() {
		pos.x = RESOL_X / 2;
		pos.y = RESOL_Y / 2;
		sobre_opc = OPC_NULL;

		for (int i{}; i < MAX_BOTON; i++) {
			presionado[i] = false;
		}
	}

	bool actualizar(ALLEGRO_EVENT ev, Pantalla& p) {
		if (ev.type == ALLEGRO_EVENT_MOUSE_AXES) {
			pos.x = ev.mouse.x / p.tam_pant_x;
			pos.y = ev.mouse.y / p.tam_pant_y;

			if (p.offset_y > 0) pos.y -= p.offset_y;
			if (pos.y < 0) pos.y = 0;
			if (pos.y > RESOL_Y) pos.y = RESOL_Y;

			return true;
		}
		return false;
	}

	inline Coord& coord() {
		return pos;
	}
};

inline bool es_oscuro(ALLEGRO_COLOR c) {
	return c.r * c.b * c.g <= .125;
}

ALLEGRO_COLOR color_oscuro(ALLEGRO_COLOR c, float osc) {
	//Encontrar mayor
	ALLEGRO_COLOR ret{ NORM_C(255) };
	double mayor{ c.r };
	if (mayor < c.b)
		mayor = c.b;
	if (mayor < c.g)
		mayor = c.g;

	double osc_p = pow(osc, 1.5);

	//Multiplicar
	ret.r = c.r * osc_p;
	ret.g = c.g * osc_p;
	ret.b = c.b * osc_p;


	//Preferencia al mayor
	if (mayor == c.r)
		ret.r = c.r * osc;
	if (mayor == c.g)
		ret.g = c.g * osc;
	if (mayor == c.b)
		ret.b = c.b * osc;

	ret.a = c.a;

	return ret;
}

ALLEGRO_COLOR operator*(ALLEGRO_COLOR a, ALLEGRO_COLOR b) {
	a.r = (a.r * b.r);
	a.g = (a.g * b.g);
	a.b = (a.b * b.b);
	a.a = (a.a * b.a);

	return a;
}

ALLEGRO_COLOR operator*(ALLEGRO_COLOR a, float b) {
	a.r *= b;
	a.g *= b;
	a.b *= b;
	a.a *= b;

	return a;
}

ostream& operator<<(ostream& out, ALLEGRO_COLOR c) {
	out << "FLUJO COLOR: " << c.r << '\t' << c.g << '\t' << c.b << endl;
	return out;
}