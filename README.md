# 🔍 Web Security Analyzer Pro

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-CC%20BY--NC%204.0-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Stable-brightgreen.svg" alt="Status">
</div>

## 📋 Descripción

**Web Security Analyzer Pro** es una herramienta avanzada de análisis de seguridad web que examina cabeceras HTTP, cookies, vulnerabilidades comunes y configuración SSL/TLS. Diseñado para administradores de sistemas, desarrolladores y profesionales de seguridad que necesitan auditar sus sitios web de forma rápida y eficiente.

### 🎯 Características Principales

- ✅ **Análisis completo de cabeceras HTTP**
- 🔒 **Detección de vulnerabilidades de seguridad** (OWASP Top 10)
- 🍪 **Análisis de cookies** con verificación de flags de seguridad
- 🔐 **Evaluación SSL/TLS** y certificados
- 📊 **Puntuación de seguridad** automática
- 🖥️ **Interfaz visual interactiva** con colores y tablas
- 📝 **Generación de reportes** en formato JSON
- 🔍 **Detección de tecnologías** y CVEs potenciales

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


