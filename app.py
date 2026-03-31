import sys
import logging
from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configuración básica de logs para la terminal
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Mapeo básico de protocolos para Análisis de Datos
PROTOCOLOS = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

def cargar_captura_red(ruta_archivo):
    """Carga el archivo PCAP y maneja errores de lectura."""
    logger.info(f"Cargando archivo de captura: {ruta_archivo}...")
    try:
        paquetes = rdpcap(ruta_archivo)
        logger.info(f"Éxito: Se cargaron {len(paquetes)} paquetes.")
        return paquetes
    except Exception as e:
        logger.error(f"Error crítico al leer el archivo: {e}")
        sys.exit(1)

def estructurar_datos_pandas(paquetes):
    """Transforma los paquetes crudos de red en un DataFrame de Pandas (Data Analysis)."""
    lista_datos = []
    
    for pkt in paquetes:
        if IP in pkt:
            fila = {
                "ip_origen": pkt[IP].src,
                "ip_destino": pkt[IP].dst,
                "protocolo": PROTOCOLOS.get(pkt[IP].proto, f"Otro({pkt[IP].proto})"),
                "tamano_bytes": len(pkt),
                "puerto_destino": pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
            }
            lista_datos.append(fila)
            
    return pd.DataFrame(lista_datos)

def analizar_trafico_general(df):
    """Calcula estadísticas generales de la red."""
    ancho_banda_total_mb = df['tamano_bytes'].sum() / (1024 * 1024)
    distribucion_protocolos = df['protocolo'].value_counts()
    
    logger.info("\n--- RESUMEN DE TRÁFICO ---")
    logger.info(f"Ancho de banda total procesado: {ancho_banda_total_mb:.2f} MB")
    logger.info("Distribución por protocolo:")
    for proto, count in distribucion_protocolos.items():
        logger.info(f"  - {proto}: {count} paquetes")
        
    return distribucion_protocolos

def detectar_amenazas_escaneo(df, limite_puertos=50):
    """Módulo de Ciberseguridad: Detecta posible escaneo de puertos (Reconocimiento)."""
    logger.info("\n--- ANÁLISIS DE SEGURIDAD ---")
    
    # Agrupamos por IP de origen y contamos cuántos puertos distintos ha tocado
    escaneos = df[df['puerto_destino'] > 0].groupby('ip_origen')['puerto_destino'].nunique()
    
    # Filtramos las IPs que superan nuestro límite de sospecha
    atacantes_potenciales = escaneos[escaneos >= limite_puertos]
    
    if not atacantes_potenciales.empty:
        logger.warning("¡ALERTA! Se detectó posible actividad de escaneo de puertos.")
        for ip, puertos_escaneados in atacantes_potenciales.items():
            logger.warning(f"  -> IP Sospechosa: {ip} (Intentó conectar a {puertos_escaneados} puertos distintos)")
            
        # Generar un log en CSV de los atacantes (Excelente para portafolio)
        atacantes_potenciales.to_csv("alerta_seguridad_ips.csv")
        logger.info("Se ha generado el reporte 'alerta_seguridad_ips.csv' con las IPs sospechosas.")
    else:
        logger.info("No se detectaron patrones obvios de escaneo de puertos.")

def generar_dashboard_visual(df, distribucion_protocolos):
    """Genera una interfaz visual profesional usando Seaborn."""
    sns.set_theme(style="whitegrid")
    fig, ejes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Dashboard de Análisis de Tráfico de Red', fontsize=16, fontweight='bold')

    # Gráfica 1: Distribución de Protocolos
    sns.barplot(x=distribucion_protocolos.index, y=distribucion_protocolos.values, ax=ejes[0], palette="viridis")
    ejes[0].set_title('Volumen de Paquetes por Protocolo')
    ejes[0].set_ylabel('Cantidad de Paquetes')
    ejes[0].set_xlabel('Protocolo')

    # Gráfica 2: Top 5 IPs con más tráfico generado (Top Talkers)
    top_ips = df['ip_origen'].value_counts().head(5)
    sns.barplot(x=top_ips.values, y=top_ips.index, ax=ejes[1], palette="magma", orient='h')
    ejes[1].set_title('Top 5 IPs Emisoras de Tráfico (Top Talkers)')
    ejes[1].set_xlabel('Cantidad de Paquetes Enviados')
    ejes[1].set_ylabel('Dirección IP Origen')

    plt.tight_layout()
    plt.show()

def main():
    if len(sys.argv) < 2:
        logger.error("Uso incorrecto. Debes proporcionar un archivo PCAP.")
        logger.error("Ejemplo: python mi_analizador.py trafico.pcap")
        sys.exit(1)
        
    archivo_pcap = sys.argv[1]
    umbral_seguridad = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    # 1. Carga de datos
    paquetes = cargar_captura_red(archivo_pcap)
    
    # 2. Análisis de Datos (Estructuración)
    df_trafico = estructurar_datos_pandas(paquetes)
    
    # 3. Métricas y visualización
    dist_proto = analizar_trafico_general(df_trafico)
    
    # 4. Módulo de Ciberseguridad
    detectar_amenazas_escaneo(df_trafico, umbral_seguridad)
    
    # 5. Desplegar Interfaz Visual
    generar_dashboard_visual(df_trafico, dist_proto)

if __name__ == "__main__":
    main()