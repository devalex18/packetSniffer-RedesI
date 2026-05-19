#!/bin/bash
echo "Instalando dependecias de Allegro 5..."

sudo apt install -y liballegro5-dev liballegro-image5-dev liballegro-font5-dev liballegro-primitives5-dev
sudo apt intall -y libpcap-dev

echo "Instalación completada, ahora es posible ejecutar 'make' para compilar el sniffer."