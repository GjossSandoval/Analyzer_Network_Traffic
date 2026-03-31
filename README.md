# Analyzer_Network_Traffic 🛡️📊

Un analizador de tráfico de red integral construido en Python que combina **Desarrollo de Software, Análisis de Datos y Ciberseguridad**.

Esta herramienta procesa archivos de captura de red (`.pcap`), estructura la información para su análisis estadístico y utiliza heurística básica para detectar posibles amenazas de seguridad, como el escaneo de puertos. Todo esto presentado en un dashboard visual e interactivo.

## ✨ Características Principales

Este proyecto aborda tres áreas clave de la tecnología:

* **Ingeniería de Software:** Código modular, manejo de excepciones y optimización al recorrer los paquetes de red una sola vez para construir un conjunto de datos centralizado mediante Python.
* **Análisis de Datos:** Uso de Pandas para transformar datos crudos de red en información estructurada. Generación de visualizaciones profesionales (volumen por protocolo y "Top Talkers") utilizando Seaborn y Matplotlib.
* **Ciberseguridad (Blue Team):** Módulo de detección de anomalías que identifica patrones de reconocimiento (Port Scanning). Genera automáticamente un artefacto de respuesta a incidentes (`alerta_seguridad_ips.csv`) con las direcciones IP sospechosas.

## 🛠️ Tecnologías y Librerías Utilizadas

* **Python 3.x:** Lenguaje principal.
* **Scapy:** Para la lectura y extracción de información de los paquetes de red.
* **Pandas:** Para la estructuración, limpieza y manipulación de los datos.
* **Matplotlib & Seaborn:** Para la renderización del dashboard y las gráficas estadísticas.

## 🚀 Instalación y Uso

**1. Clonar el repositorio y preparar el entorno**
Asegúrate de tener Python instalado. Luego, instala las dependencias necesarias ejecutando el siguiente comando en tu terminal:

```bash
pip install scapy pandas matplotlib seaborn
