# 🔍 Web Security Analyzer Pro v3.0

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-CC%20BY--NC%204.0-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Stable-brightgreen.svg" alt="Status">
</div>

## 📋 Descripción

**Web Security Analyzer Pro** es una herramienta avanzada de análisis de seguridad web que examina cabeceras HTTP, cookies, vulnerabilidades comunes y configuración SSL/TLS. Diseñado para administradores de sistemas, desarrolladores y profesionales de seguridad que necesitan auditar sus sitios web de forma rápida y eficiente.

El script Web Security Analyzer Pro realiza un análisis exhaustivo de seguridad web sin consultas externas, basándose únicamente en la respuesta HTTP y el contenido de la página. Comprueba cabeceras HTTP (HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, CSP, Referrer-Policy), cookies (flags Secure, HttpOnly y SameSite), SSL/TLS (versión del protocolo y validez del certificado), vulnerabilidades comunes (Clickjacking, MIME sniffing, XSS, información del servidor expuesta), contenido HTML (metadatos, títulos, recursos como CSS, JS e imágenes), tecnologías detectadas y genera una puntuación de seguridad con recomendaciones de remediación. Los CVEs mostrados son simulados (datos hardcodeados) y el script no consulta bases de datos externas como NVD, VirusTotal o Shodan, aunque sería interesante integrarlas, no?.

### 🎯 Características Principales

- Análisis completo de cabeceras HTTP
- Detección de vulnerabilidades (OWASP Top 10)
- Análisis de cookies y seguridad
- Puntuación de seguridad automática
- Detección de tecnologías
- Búsqueda de CVEs offline con FKIE-CAD
- Base de datos con 381,325 CVEs
- Paginación en resultados
- Reportes en JSON
- Interfaz visual interactiva con Rich

## 👤 Autor

**David Casas M.**  
Competencia Digital  
[LinkedIn](https://es.linkedin.com/in/davidcasas-competenciadigital/es)

## 📄 Licencia

Este proyecto está bajo la licencia **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

- ✅ **Permitido**: Compartir, copiar y redistribuir el material
- ✅ **Permitido**: Adaptar, remezclar y transformar el material
- ❌ **Restringido**: Uso comercial
- ✅ **Requerido**: Atribución al autor original

Para más detalles, consulta el archivo [LICENSE](LICENSE).

## 🚀 Instalación Rápida

### Requisitos Previos

- Python 3.8 o superior
- pip (gestor de paquetes de Python)
- Conexión a Internet (para análisis de sitios web)

### Instalación con Entorno Virtual (Recomendado)

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/web-security-analyzer.git
cd web-security-analyzer

# 2. Crear entorno virtual
python3 -m venv websecurity

# 3. Activar entorno virtual
# En Linux/Mac:
source websecurity/bin/activate
# En Windows:
venv\Scripts\activate

# 4. Instalar dependencias
pip install -r requirements.txt

# 5. Ejecutar el analizador
python web_analyzer_visual.py

### Instalación sin entorno virtual (global)
```bash
# Instalar dependencias globalmente
pip install rich requests

# Ejecutar
python web_analyzer_visual.py

Dependencias

    requests >= 2.28.0
    rich >= 13.0.0

$ python web_analyzer_visual.py

╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗    ██╗███████╗██████╗     ███████╗███████╗ ██████╗██╗   ██╗██████╗   ║
║   ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗  ║
║   ██║ █╗ ██║█████╗  ██████╔╝    ███████╗█████╗  ██║     ██║   ██║██████╔╝  ║
║   ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗  ║
║   ╚███╔███╔╝███████╗██████╔╝    ███████║███████╗╚██████╗╚██████╔╝██║  ██║  ║
║    ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝  ║
║                                                                              ║
║                    🔍 Análisis Web de Seguridad Pro                          ║
║                   Interactive Security Scanner v2.0                         ║
║                                                                              ║
║               Autor: David Casas M. - Competencia Digital                   ║
║               Licencia: CC BY-NC 4.0                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝



[bold cyan]Selecciona una opción[/bold cyan] [1/2/3/4/5/6/7] (1): 1

[bold]Ingresa la URL a analizar[/bold]: https://www.website.com

El modo interactivo te guiará a través de un menú con las siguientes opciones:

    Analizar nueva URL
    Ver cabeceras HTTP
    Análisis de seguridad
    Vulnerabilidades encontradas
    CVEs detectados
    Generar reporte
    Salir

Reportes Generados

Los reportes se guardan automáticamente en formato JSON:
{
  "url": "https://www.website.com",
  "timestamp": "2026-08-07T19:33:46.123456",
  "status": 200,
  "headers": {
    "server": "nginx",
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "x-xss-protection": "1; mode=block",
    "referrer-policy": "strict-origin-when-cross-origin"
  },
  "vulnerabilities": [
    {
      "type": "HSTS no configurado",
      "severity": "Media",
      "description": "HTTP Strict Transport Security no está habilitado",
      "remediation": "Agregar header Strict-Transport-Security con max-age"
    }
  ],
  "score": "4/6"
}

Interpretación de Resultados

Cabeceras de Seguridad
Cabecera	Función	Recomendación
Strict-Transport-Security	Fuerza HTTPS	Configurar con max-age ≥ 31536000
X-Frame-Options	Previene Clickjacking	Usar DENY o SAMEORIGIN
X-Content-Type-Options	Previene MIME sniffing	Usar nosniff
X-XSS-Protection	Protección contra XSS	Usar 1; mode=block
Content-Security-Policy	Política de seguridad	Implementar según necesidades
Referrer-Policy	Control de información de referencia	Usar strict-origin-when-cross-origin

Niveles de Severidad

    🟢 Baja: Recomendaciones de mejora
    🟡 Media: Configuraciones mejorables
    🟠 Alta: Vulnerabilidades importantes
    🔴 Crítica: Riesgos de seguridad graves

Puntuación de Seguridad

    90-100%: 🟢 Excelente - Seguridad robusta
    70-89%: 🟡 Bueno - Mejorable
    50-69%: 🟠 Regular - Atención requerida
    0-49%: 🔴 Deficiente - Acción inmediata

Contribuciones

Las contribuciones son bienvenidas. Por favor:

    Haz un Fork del proyecto
    Crea tu rama de características (git checkout -b feature/AmazingFeature)
    Commit tus cambios (git commit -m 'Add some AmazingFeature')
    Push a la rama (git push origin feature/AmazingFeature)
    Abre un Pull Request

Buenas Prácticas

Consideraciones de Seguridad

    Autorización: Solo analiza sitios web sobre los que tengas permiso explícito
    Uso Responsable: Esta herramienta es para auditoría y aprendizaje
    Privacidad: No almacena información personal de los sitios analizados

Recomendaciones

    Entorno Virtual: Siempre usa venv para evitar conflictos de dependencias
    Actualizaciones: Mantén las dependencias actualizadas
    Pruebas: Verifica el script en un entorno de prueba antes de usarlo en producción
    Documentación: Documenta tus hallazgos y configuraciones

Reporte de Errores

Si encuentras algún error, por favor crea un issue en GitHub con:

    Descripción del problema

    Pasos para reproducirlo

    Versión de Python y sistema operativo

    Salida de error completa

    URL analizada (si es pública)

Aviso Legal

Esta herramienta se proporciona "tal cual", sin garantías de ningún tipo. El autor no se hace responsable del mal uso de la herramienta. Úsala de manera responsable y ética.

IMPORTANTE: El análisis de seguridad de sitios web sin autorización explícita puede ser ilegal en muchas jurisdicciones. Asegúrate de tener permiso antes de analizar cualquier sitio que no sea de tu propiedad.

Agradecimientos

    A la comunidad de Python por las excelentes librerías

    A los contribuidores y colaboradores

    A los usuarios que reportan bugs y sugieren mejoras

    A la comunidad de Odoo por sus valiosas contribuciones a la seguridadUpdate

Estado del Proyecto

Métrica	Estado
Versión	1.0.0
Estado	Estable
Pruebas	✅ Pasadas
Documentación	✅ Completa
Soporte	Activo

Enlaces Útiles

    OWASP Top 10
    Security Headers
    SSL Labs
    HSTS Preload
    Mozilla Observatory


