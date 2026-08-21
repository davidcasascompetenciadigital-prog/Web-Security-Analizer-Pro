#!/usr/bin/env python3
"""
Web Security Analyzer Pro - Versión Final con CVEs bajo demanda
Análisis completo de cabeceras, vulnerabilidades y CVEs en tiempo real

Autor: David Casas M. - Competencia Digital
Licencia: CC BY-NC 4.0
"""

import requests
import json
import time
import re
import subprocess
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
import warnings
warnings.filterwarnings('ignore')

# Importar módulo de CVEs
from cve_analyzer import LocalCVEDatabase

# Librerías para interfaz visual
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Rich no está instalado. Instalando...")
    subprocess.check_call(['pip', 'install', 'rich'])
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich import box
    RICH_AVAILABLE = True

console = Console()


class WebSecurityAnalyzer:
    """Analizador web completo con soporte para CVEs"""

    def __init__(self):
        self.url = None
        self.session = requests.Session()
        self.results = {}
        self.vulnerabilities = []
        self.security_score = 0
        self.max_score = 0
        self.response = None
        self.headers = {}
        self.classified_headers = {}
        self.security_checks = {}
        self.status_code = None
        self.response_time = 0
        self.final_url = None
        self.technologies = []

        # Inicializar base de datos de CVEs
        self.cve_db = LocalCVEDatabase(cache_dir="./cve_cache")
        self.cve_db_loaded = False
        self.cve_results = {}
        self.cves_searched = False

    def run(self):
        """Ejecuta el programa interactivo"""
        self.show_banner()

        while True:
            self.show_main_menu()
            choice = Prompt.ask(
                "\n[bold cyan]Selecciona una opción[/bold cyan]",
                choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"],
                default="1"
            )

            if choice == "1":
                self.analyze_website()
            elif choice == "2":
                self.show_headers_detail()
            elif choice == "3":
                self.show_security_detail()
            elif choice == "4":
                self.show_vulnerabilities_detail()
            elif choice == "5":
                self.search_and_show_cves()
            elif choice == "6":
                self.generate_report()
            elif choice == "7":
                self.manage_cve_database()
            elif choice == "8":
                self.show_cves_detail()
            elif choice == "9":
                if Confirm.ask("[yellow]¿Estás seguro de que quieres salir?[/yellow]"):
                    console.print("\n[bold green]¡Hasta luego! 👋[/bold green]")
                    break

    def show_banner(self):
        """Muestra el banner de bienvenida"""
        console.clear()
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗    ██╗███████╗██████╗     ███████╗███████╗ ██████╗██╗   ██╗██████╗   ║
║   ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗  ║
║   ██║ █╗ ██║█████╗  ██████╔╝    ███████╗█████╗  ██║     ██║   ██║██████╔╝  ║
║   ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗  ║
║   ╚███╔███╔╝███████╗██████╔╝    ███████║███████╗╚██████╗╚██████╔╝██║  ██║  ║
║    ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝  ║
║                                                                              ║
║                    🔍 Web Security Analyzer Pro                             ║
║                   v3.0 - Con Análisis de CVEs                               ║
║                                                                              ║
║               Autor: David Casas M. - Competencia Digital                   ║
║               Licencia: CC BY-NC 4.0                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold cyan", border_style="cyan"))
        console.print("\n[italic]Análisis completo de cabeceras, vulnerabilidades y CVEs[/italic]\n")

    def show_main_menu(self):
        """Muestra el menú principal"""
        menu = Table(show_header=False, box=box.ROUNDED, style="bright_blue")
        menu.add_column("Opción", style="bold cyan", width=10)
        menu.add_column("Descripción", style="white")

        menu.add_row("1", "🔍 Analizar nueva URL")
        menu.add_row("2", "📋 Ver cabeceras HTTP")
        menu.add_row("3", "🔒 Análisis de seguridad")
        menu.add_row("4", "⚠️  Vulnerabilidades encontradas")
        menu.add_row("5", "🔎 Buscar CVEs para tecnologías detectadas")
        menu.add_row("6", "📊 Generar reporte")
        menu.add_row("7", "💾 Gestionar base de datos CVEs")
        menu.add_row("8", "📌 Ver CVEs encontrados")
        menu.add_row("9", "🚪 Salir")

        console.print(Panel(menu, title="[bold]MENÚ PRINCIPAL[/bold]", border_style="cyan"))

    # =====================================================
    # GESTIÓN DE BASE DE DATOS CVEs
    # =====================================================

    def manage_cve_database(self):
        """Gestiona la base de datos local de CVEs"""
        console.clear()
        self.show_banner()

        console.print(Panel("[bold magenta]📌 GESTIÓN DE BASE DE DATOS CVEs[/bold magenta]", border_style="magenta"))

        # Información del origen de la base de datos
        info_panel = Panel(
            """
[bold cyan]📌 ORIGEN DE LA BASE DE DATOS[/bold cyan]

[bold]Fuente:[/bold] FKIE-CAD (Fraunhofer FKIE Cyber Analysis & Defense)
[bold]Repositorio:[/bold] https://github.com/fkie-cad/nvd-json-data-feeds
[bold]Descripción:[/bold] Reconstrucción comunitaria de los feeds JSON de NVD
[bold]Actualización:[/bold] Diaria (00:00 UTC)
[bold]Total CVEs:[/bold] ~381,000+
[bold]Formato:[/bold] NVD JSON 2.0
[bold]Licencia:[/bold] Open Source
[bold]Ventajas:[/bold]
   • No requiere autenticación API
   • Sin límites de peticiones
   • Búsqueda offline
   • Actualizaciones automáticas

[italic dim]Los datos se sincronizan con NVD (National Vulnerability Database)
https://nvd.nist.gov/[/italic dim]
            """,
            title="[bold]📚 FUENTE DE DATOS[/bold]",
            border_style="cyan"
        )
        console.print(info_panel)

        # Verificar estado actual
        needs_update, message = self.cve_db.check_update_needed()

        status_table = Table(box=box.ROUNDED)
        status_table.add_column("Elemento", style="bold cyan")
        status_table.add_column("Estado", style="white")

        status_table.add_row("📁 Archivo local", "✅" if self.cve_db.cves_file.exists() else "❌")
        status_table.add_row("📊 Versión", self.cve_db.version or "No disponible")
        status_table.add_row("🔄 Actualización", message)

        if self.cve_db.cves_file.exists():
            size_mb = self.cve_db.cves_file.stat().st_size / (1024 * 1024)
            status_table.add_row("📦 Tamaño", f"{size_mb:.1f} MB")

        console.print(Panel(status_table, title="[bold]📊 ESTADO[/bold]", border_style="cyan"))

        # Mostrar estadísticas si está disponible
        stats = self.cve_db.get_statistics()
        if stats.get('status') != 'No cargada' and stats.get('total_cves', 0) > 0:
            stats_table = Table(box=box.SIMPLE)
            stats_table.add_column("Métrica", style="bold yellow")
            stats_table.add_column("Valor", style="white")

            stats_table.add_row("Total CVEs", str(stats['total_cves']))
            if 'severity_count' in stats:
                for severity, count in stats['severity_count'].items():
                    if count > 0:
                        color = "red" if severity == "CRITICAL" else "yellow" if severity == "HIGH" else "blue"
                        stats_table.add_row(f"  {severity}", f"[{color}]{count}[/{color}]")

            console.print(Panel(stats_table, title="[bold]📊 ESTADÍSTICAS[/bold]", border_style="green"))

        # Opciones
        console.print("\n[bold]Opciones:[/bold]")
        console.print("  1. 📥 Descargar/Actualizar base de datos")
        console.print("  2. 🔍 Buscar CVEs para tecnologías detectadas")
        console.print("  3. 📊 Ver estadísticas detalladas")
        console.print("  4. ↩️  Volver al menú principal")

        choice = Prompt.ask("\n[bold cyan]Selecciona una opción[/bold cyan]", choices=["1", "2", "3", "4"])

        if choice == "1":
            if self.cve_db.download_cves(force=True):
                self.cve_db_loaded = True
                console.print("[bold green]✅ Base de datos actualizada correctamente[/bold green]")
            else:
                console.print("[bold red]❌ Error actualizando base de datos[/bold red]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")

        elif choice == "2":
            if not self.cve_db_loaded:
                self.cve_db.load_cves()
                self.cve_db_loaded = True
            self.search_and_show_cves()

        elif choice == "3":
            self.show_cve_statistics()

        elif choice == "4":
            return

    def show_cve_statistics(self):
        """Muestra estadísticas detalladas de la base de datos CVEs"""
        console.clear()
        self.show_banner()

        console.print(Panel("[bold green]📊 ESTADÍSTICAS DE BASE DE DATOS CVEs[/bold green]", border_style="green"))

        stats = self.cve_db.get_statistics()

        if stats.get('status') == 'No cargada' or stats.get('total_cves', 0) == 0:
            console.print("[yellow]⚠️  Base de datos no cargada o no disponible[/yellow]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return

        stats_table = Table(box=box.ROUNDED)
        stats_table.add_column("Métrica", style="bold cyan")
        stats_table.add_column("Valor", style="white")

        stats_table.add_row("📊 Total CVEs", str(stats['total_cves']))
        stats_table.add_row("📅 Última actualización", stats.get('last_update', 'N/A'))
        stats_table.add_row("📌 Versión", stats.get('version', 'N/A'))

        if 'severity_count' in stats and stats['total_cves'] > 0:
            for severity, count in stats['severity_count'].items():
                if count > 0:
                    color = "red" if severity == "CRITICAL" else "yellow" if severity == "HIGH" else "blue" if severity == "MEDIUM" else "green"
                    percent = (count / stats['total_cves']) * 100
                    stats_table.add_row(
                        f"  {severity}",
                        f"[{color}]{count} ({percent:.1f}%)[/{color}]"
                    )

        console.print(Panel(stats_table, title="[bold]📊 ESTADÍSTICAS[/bold]", border_style="cyan"))

        if self.cve_db.cves_file.exists():
            size_mb = self.cve_db.cves_file.stat().st_size / (1024 * 1024)
            console.print(Panel(
                f"""
[bold]Información de archivo:[/bold]
📁 Ruta: {self.cve_db.cves_file}
📦 Tamaño: {size_mb:.1f} MB
                """,
                title="[bold]📁 ARCHIVO LOCAL[/bold]",
                border_style="dim"
            ))

        input("\n[dim]Presiona Enter para continuar...[/dim]")

    # =====================================================
    # ANÁLISIS PRINCIPAL
    # =====================================================

    def analyze_website(self):
        """Analiza una URL ingresada por el usuario - SIN búsqueda automática de CVEs"""
        console.clear()
        self.show_banner()

        console.print(Panel("[bold cyan]NUEVO ANÁLISIS[/bold cyan]", border_style="cyan"))

        self.url = Prompt.ask("\n[bold]Ingresa la URL a analizar[/bold]", default="https://httpbin.org/headers")

        if not self.url.startswith(('http://', 'https://')):
            self.url = 'https://' + self.url

        console.print(f"\n[italic]Analizando: {self.url}[/italic]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:

            task = progress.add_task("[cyan]Conectando...", total=100)
            progress.update(task, advance=10)
            time.sleep(0.5)

            self.response = self.make_request()
            progress.update(task, advance=30)
            time.sleep(0.5)

            if self.response:
                self.analyze_headers(self.response)
                progress.update(task, advance=45)
                time.sleep(0.5)

                self.analyze_security(self.response)
                progress.update(task, advance=55)
                time.sleep(0.5)

                self.analyze_vulnerabilities()
                progress.update(task, advance=65)
                time.sleep(0.5)

                # Detección de tecnologías con pausas internas
                self.detect_technologies()
                progress.update(task, advance=75)
                time.sleep(0.5)

                progress.update(task, advance=90)
                time.sleep(0.5)

        # Mostrar resumen (sin CVEs)
        self.show_analysis_summary()

        # Preguntar si quiere buscar CVEs ahora
        if self.technologies:
            if Confirm.ask("\n[bold]¿Quieres buscar CVEs para las tecnologías detectadas?[/bold]"):
                self.search_and_show_cves()
        else:
            console.print("\n[yellow]⚠️  No se detectaron tecnologías para buscar CVEs[/yellow]")

        if Confirm.ask("\n[bold]¿Quieres ver el análisis detallado?[/bold]"):
            self.show_detailed_analysis()

    def make_request(self):
        """Realiza la petición HTTP"""
        try:
            start_time = time.time()
            response = self.session.get(
                self.url,
                timeout=15,
                allow_redirects=True,
                headers={'User-Agent': 'WebSecurityAnalyzer/3.0'}
            )
            self.response_time = time.time() - start_time
            self.status_code = response.status_code
            self.final_url = response.url
            return response
        except Exception as e:
            console.print(f"[red]❌ Error: {str(e)}[/red]")
            return None

    def analyze_headers(self, response):
        """Analiza las cabeceras HTTP"""
        self.headers = dict(response.headers)

        self.classified_headers = defaultdict(list)
        categories = {
            'General': ['server', 'date', 'content-type', 'content-length', 'connection'],
            'Caché': ['cache-control', 'expires', 'pragma', 'age', 'last-modified'],
            'Seguridad': ['strict-transport-security', 'x-frame-options', 'x-content-type-options',
                         'x-xss-protection', 'content-security-policy', 'referrer-policy'],
            'CORS': ['access-control-allow-origin', 'access-control-allow-methods'],
            'Cookies': ['set-cookie'],
            'Compresión': ['content-encoding', 'accept-encoding', 'transfer-encoding']
        }

        for key, value in self.headers.items():
            key_lower = key.lower()
            categorized = False
            for category, cat_headers in categories.items():
                if key_lower in [h.lower() for h in cat_headers]:
                    self.classified_headers[category].append((key, value))
                    categorized = True
                    break
            if not categorized:
                self.classified_headers['Otros'].append((key, value))

    def analyze_security(self, response):
        """Análisis de seguridad básico"""
        self.security_checks = {
            'HTTPS': self.url.startswith('https'),
            'HSTS': 'strict-transport-security' in response.headers,
            'X-Frame-Options': 'x-frame-options' in response.headers,
            'X-Content-Type-Options': 'x-content-type-options' in response.headers,
            'X-XSS-Protection': 'x-xss-protection' in response.headers,
            'CSP': 'content-security-policy' in response.headers,
            'Referrer-Policy': 'referrer-policy' in response.headers
        }

        self.security_score = sum(1 for v in self.security_checks.values() if v)
        self.max_score = len(self.security_checks)

    def analyze_vulnerabilities(self):
        """Análisis de vulnerabilidades"""
        self.vulnerabilities = []

        if not self.security_checks.get('HSTS', False):
            self.vulnerabilities.append({
                'type': 'HSTS no configurado',
                'severity': 'Media',
                'description': 'HTTP Strict Transport Security no está habilitado',
                'remediation': 'Agregar header Strict-Transport-Security con max-age'
            })

        if not self.security_checks.get('X-Frame-Options', False):
            self.vulnerabilities.append({
                'type': 'Riesgo de Clickjacking',
                'severity': 'Alta',
                'description': 'X-Frame-Options no configurado, riesgo de clickjacking',
                'remediation': 'Configurar X-Frame-Options: DENY o SAMEORIGIN'
            })

        if not self.security_checks.get('X-Content-Type-Options', False):
            self.vulnerabilities.append({
                'type': 'MIME Sniffing',
                'severity': 'Media',
                'description': 'X-Content-Type-Options no configurado',
                'remediation': 'Configurar X-Content-Type-Options: nosniff'
            })

        if not self.security_checks.get('X-XSS-Protection', False):
            self.vulnerabilities.append({
                'type': 'Protección XSS',
                'severity': 'Media',
                'description': 'X-XSS-Protection no configurado',
                'remediation': 'Configurar X-XSS-Protection: 1; mode=block'
            })

        if not self.security_checks.get('Referrer-Policy', False):
            self.vulnerabilities.append({
                'type': 'Referrer-Policy no configurado',
                'severity': 'Baja',
                'description': 'Referrer-Policy no configurado',
                'remediation': 'Configurar Referrer-Policy: strict-origin-when-cross-origin'
            })

        if 'server' in self.headers:
            self.vulnerabilities.append({
                'type': 'Información del servidor expuesta',
                'severity': 'Baja',
                'description': f'Servidor: {self.headers["server"]}',
                'remediation': 'Ocultar información del servidor en la configuración'
            })

        if self.response and self.response.cookies:
            for cookie in self.response.cookies:
                if not cookie.secure and self.url.startswith('https'):
                    self.vulnerabilities.append({
                        'type': f'Cookie {cookie.name} sin Secure',
                        'severity': 'Media',
                        'description': f'Cookie {cookie.name} no tiene flag Secure',
                        'remediation': 'Agregar flag Secure a la cookie'
                    })
                if not cookie.has_nonstandard_attr('httponly'):
                    self.vulnerabilities.append({
                        'type': f'Cookie {cookie.name} sin HttpOnly',
                        'severity': 'Media',
                        'description': f'Cookie {cookie.name} accesible por JavaScript',
                        'remediation': 'Agregar flag HttpOnly a la cookie'
                    })

    # =====================================================
    # DETECCIÓN DE TECNOLOGÍAS - VERSIÓN COMPLETA Y CORREGIDA
    # =====================================================

    def detect_technologies(self):
        """Detecta tecnologías del sitio web - Con prioridad a cabeceras HTTP"""
        self.technologies = []
        detected = set()  # Para evitar duplicados
        
        console.print("\n[bold cyan]🔍 Detectando tecnologías...[/bold cyan]")
        time.sleep(0.5)

        # =====================================================
        # 1. PRIORIDAD ALTA: SERVICIOS WEB DESDE CABECERAS
        # =====================================================
        
        if 'server' in self.headers:
            server = self.headers['server']
            server_lower = server.lower()
            
            # nginx - SIEMPRE detectar si está en la cabecera
            if 'nginx' in server_lower:
                version = 'unknown'
                # Extraer versión: "nginx/1.18.0" -> "1.18.0"
                parts = server.split('/')
                if len(parts) >= 2:
                    # Limpiar la versión (quitar espacios y caracteres extraños)
                    version = parts[1].split()[0].strip()
                self.technologies.append(('nginx', version))
                detected.add('nginx')
                console.print(f"   [green]✅ Detectado (Server header):[/green] nginx [dim]versión {version}[/dim]")
                time.sleep(0.3)
            
            # Apache
            if 'apache' in server_lower and 'apache' not in detected:
                version = 'unknown'
                parts = server.split('/')
                if len(parts) >= 2:
                    version = parts[1].split()[0].strip()
                self.technologies.append(('apache', version))
                detected.add('apache')
                console.print(f"   [green]✅ Detectado (Server header):[/green] apache [dim]versión {version}[/dim]")
                time.sleep(0.3)
            
            # Caddy
            if 'caddy' in server_lower and 'caddy' not in detected:
                self.technologies.append(('caddy', 'unknown'))
                detected.add('caddy')
                console.print(f"   [green]✅ Detectado (Server header):[/green] caddy")
                time.sleep(0.3)
            
            # IIS (Windows)
            if 'iis' in server_lower and 'iis' not in detected:
                version = 'unknown'
                parts = server.split('/')
                if len(parts) >= 2:
                    version = parts[1].split()[0].strip()
                self.technologies.append(('iis', version))
                detected.add('iis')
                console.print(f"   [green]✅ Detectado (Server header):[/green] iis [dim]versión {version}[/dim]")
                time.sleep(0.3)
            
            # Tomcat
            if 'tomcat' in server_lower and 'tomcat' not in detected:
                version = 'unknown'
                parts = server.split('/')
                if len(parts) >= 2:
                    version = parts[1].split()[0].strip()
                self.technologies.append(('tomcat', version))
                detected.add('tomcat')
                console.print(f"   [green]✅ Detectado (Server header):[/green] tomcat [dim]versión {version}[/dim]")
                time.sleep(0.3)
            
            # Otros servidores
            other_servers = ['lighttpd', 'gunicorn', 'uwsgi', 'jetty', 'resin', 'weblogic', 'websphere', 'kestrel']
            for srv in other_servers:
                if srv in server_lower and srv not in detected:
                    version = 'unknown'
                    parts = server.split('/')
                    if len(parts) >= 2:
                        version = parts[1].split()[0].strip()
                    self.technologies.append((srv, version))
                    detected.add(srv)
                    console.print(f"   [green]✅ Detectado (Server header):[/green] {srv} [dim]versión {version}[/dim]")
                    time.sleep(0.3)

        # =====================================================
        # 2. LENGUAJES DE PROGRAMACIÓN (desde cabeceras)
        # =====================================================
        
        if 'x-powered-by' in self.headers:
            xpowered = self.headers['x-powered-by'].lower()
            
            # PHP
            if 'php' in xpowered and 'php' not in detected:
                version = 'unknown'
                parts = self.headers['x-powered-by'].split('/')
                if len(parts) >= 2:
                    version = parts[1].split()[0].strip()
                self.technologies.append(('php', version))
                detected.add('php')
                console.print(f"   [green]✅ Detectado (X-Powered-By):[/green] php [dim]versión {version}[/dim]")
                time.sleep(0.3)
            
            # Node.js / Express
            if ('express' in xpowered or 'node' in xpowered) and 'nodejs' not in detected:
                self.technologies.append(('nodejs', 'unknown'))
                detected.add('nodejs')
                console.print(f"   [green]✅ Detectado (X-Powered-By):[/green] nodejs")
                time.sleep(0.3)
            
            # Ruby on Rails
            if 'rails' in xpowered and 'rails' not in detected:
                self.technologies.append(('rails', 'unknown'))
                detected.add('rails')
                console.print(f"   [green]✅ Detectado (X-Powered-By):[/green] rails")
                time.sleep(0.3)
            
            # Python (Django, Flask, etc.)
            if 'python' in xpowered and 'python' not in detected:
                self.technologies.append(('python', 'unknown'))
                detected.add('python')
                console.print(f"   [green]✅ Detectado (X-Powered-By):[/green] python")
                time.sleep(0.3)
            
            # ASP.NET
            if 'asp.net' in xpowered and 'aspnet' not in detected:
                self.technologies.append(('aspnet', 'unknown'))
                detected.add('aspnet')
                console.print(f"   [green]✅ Detectado (X-Powered-By):[/green] asp.net")
                time.sleep(0.3)

        # =====================================================
        # 3. SISTEMAS OPERATIVOS (desde cabeceras)
        # =====================================================
        
        if 'server' in self.headers:
            server_lower = self.headers['server'].lower()
            if 'ubuntu' in server_lower and 'ubuntu' not in detected:
                self.technologies.append(('ubuntu', 'unknown'))
                detected.add('ubuntu')
                console.print(f"   [green]✅ Detectado:[/green] ubuntu")
                time.sleep(0.3)
            elif 'debian' in server_lower and 'debian' not in detected:
                self.technologies.append(('debian', 'unknown'))
                detected.add('debian')
                console.print(f"   [green]✅ Detectado:[/green] debian")
                time.sleep(0.3)
            elif 'centos' in server_lower and 'centos' not in detected:
                self.technologies.append(('centos', 'unknown'))
                detected.add('centos')
                console.print(f"   [green]✅ Detectado:[/green] centos")
                time.sleep(0.3)
            elif 'red hat' in server_lower and 'redhat' not in detected:
                self.technologies.append(('redhat', 'unknown'))
                detected.add('redhat')
                console.print(f"   [green]✅ Detectado:[/green] redhat")
                time.sleep(0.3)

        # =====================================================
        # 4. CDN Y SERVICIOS
        # =====================================================
        
        if 'server' in self.headers:
            server_lower = self.headers['server'].lower()
            if 'cloudflare' in server_lower and 'cloudflare' not in detected:
                self.technologies.append(('cloudflare', 'unknown'))
                detected.add('cloudflare')
                console.print(f"   [green]✅ Detectado:[/green] cloudflare")
                time.sleep(0.3)
            
            if 'amazon' in server_lower and 'aws' not in detected:
                self.technologies.append(('aws', 'unknown'))
                detected.add('aws')
                console.print(f"   [green]✅ Detectado:[/green] aws")
                time.sleep(0.3)

        # =====================================================
        # 5. CMS Y PLATAFORMAS (desde contenido HTML)
        # =====================================================
        
        if self.response:
            content = self.response.text.lower()
            
            # WordPress
            if ('wp-content' in content or 'wp-includes' in content) and 'wordpress' not in detected:
                version = self._extract_wordpress_version(self.response.text)
                self.technologies.append(('wordpress', version or 'unknown'))
                detected.add('wordpress')
                console.print(f"   [green]✅ Detectado (HTML):[/green] wordpress [dim]versión {version or 'unknown'}[/dim]")
                time.sleep(0.3)
            
            # Odoo
            if 'odoo' in content and 'odoo' not in detected:
                version = self._extract_odoo_version(self.response.text)
                self.technologies.append(('odoo', version or 'unknown'))
                detected.add('odoo')
                console.print(f"   [green]✅ Detectado (HTML):[/green] odoo [dim]versión {version or 'unknown'}[/dim]")
                time.sleep(0.3)
            
            # Django
            if 'django' in content and 'django' not in detected:
                self.technologies.append(('django', 'unknown'))
                detected.add('django')
                console.print(f"   [green]✅ Detectado (HTML):[/green] django")
                time.sleep(0.3)
            
            # Drupal
            if 'drupal' in content and 'drupal' not in detected:
                self.technologies.append(('drupal', 'unknown'))
                detected.add('drupal')
                console.print(f"   [green]✅ Detectado (HTML):[/green] drupal")
                time.sleep(0.3)
            
            # Joomla
            if 'joomla' in content and 'joomla' not in detected:
                self.technologies.append(('joomla', 'unknown'))
                detected.add('joomla')
                console.print(f"   [green]✅ Detectado (HTML):[/green] joomla")
                time.sleep(0.3)
            
            # Magento
            if 'magento' in content and 'magento' not in detected:
                self.technologies.append(('magento', 'unknown'))
                detected.add('magento')
                console.print(f"   [green]✅ Detectado (HTML):[/green] magento")
                time.sleep(0.3)
            
            # PrestaShop
            if 'prestashop' in content and 'prestashop' not in detected:
                self.technologies.append(('prestashop', 'unknown'))
                detected.add('prestashop')
                console.print(f"   [green]✅ Detectado (HTML):[/green] prestashop")
                time.sleep(0.3)
            
            # Shopify
            if 'shopify' in content and 'shopify' not in detected:
                self.technologies.append(('shopify', 'unknown'))
                detected.add('shopify')
                console.print(f"   [green]✅ Detectado (HTML):[/green] shopify")
                time.sleep(0.3)
            
            # Laravel
            if 'laravel' in content and 'laravel' not in detected:
                self.technologies.append(('laravel', 'unknown'))
                detected.add('laravel')
                console.print(f"   [green]✅ Detectado (HTML):[/green] laravel")
                time.sleep(0.3)
            
            # Symfony
            if 'symfony' in content and 'symfony' not in detected:
                self.technologies.append(('symfony', 'unknown'))
                detected.add('symfony')
                console.print(f"   [green]✅ Detectado (HTML):[/green] symfony")
                time.sleep(0.3)
            
            # Flask
            if 'flask' in content and 'flask' not in detected:
                self.technologies.append(('flask', 'unknown'))
                detected.add('flask')
                console.print(f"   [green]✅ Detectado (HTML):[/green] flask")
                time.sleep(0.3)
            
            # Vue.js
            if 'vue' in content and 'vuejs' not in detected:
                self.technologies.append(('vuejs', 'unknown'))
                detected.add('vuejs')
                console.print(f"   [green]✅ Detectado (HTML):[/green] vuejs")
                time.sleep(0.3)
            
            # React
            if 'react' in content and 'react' not in detected:
                self.technologies.append(('react', 'unknown'))
                detected.add('react')
                console.print(f"   [green]✅ Detectado (HTML):[/green] react")
                time.sleep(0.3)
            
            # Angular
            if 'angular' in content and 'angular' not in detected:
                self.technologies.append(('angular', 'unknown'))
                detected.add('angular')
                console.print(f"   [green]✅ Detectado (HTML):[/green] angular")
                time.sleep(0.3)
            
            # Bootstrap
            if 'bootstrap' in content and 'bootstrap' not in detected:
                self.technologies.append(('bootstrap', 'unknown'))
                detected.add('bootstrap')
                console.print(f"   [green]✅ Detectado (HTML):[/green] bootstrap")
                time.sleep(0.3)
            
            # jQuery
            if 'jquery' in content and 'jquery' not in detected:
                self.technologies.append(('jquery', 'unknown'))
                detected.add('jquery')
                console.print(f"   [green]✅ Detectado (HTML):[/green] jquery")
                time.sleep(0.3)

        # =====================================================
        # 6. DETECCIÓN DESDE META GENERATOR (fallback)
        # =====================================================
        
        if self.response:
            match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', 
                            self.response.text, re.IGNORECASE)
            if match:
                generator = match.group(1).lower()
                if 'wordpress' in generator and 'wordpress' not in detected:
                    version = self._extract_wordpress_version(self.response.text)
                    self.technologies.append(('wordpress', version or 'unknown'))
                    detected.add('wordpress')
                    console.print(f"   [green]✅ Detectado (meta):[/green] wordpress [dim]versión {version or 'unknown'}[/dim]")
                    time.sleep(0.3)
                elif 'odoo' in generator and 'odoo' not in detected:
                    version = self._extract_odoo_version(self.response.text)
                    self.technologies.append(('odoo', version or 'unknown'))
                    detected.add('odoo')
                    console.print(f"   [green]✅ Detectado (meta):[/green] odoo [dim]versión {version or 'unknown'}[/dim]")
                    time.sleep(0.3)
                elif 'drupal' in generator and 'drupal' not in detected:
                    self.technologies.append(('drupal', 'unknown'))
                    detected.add('drupal')
                    console.print(f"   [green]✅ Detectado (meta):[/green] drupal")
                    time.sleep(0.3)
                elif 'joomla' in generator and 'joomla' not in detected:
                    self.technologies.append(('joomla', 'unknown'))
                    detected.add('joomla')
                    console.print(f"   [green]✅ Detectado (meta):[/green] joomla")
                    time.sleep(0.3)

        # =====================================================
        # 7. BASES DE DATOS (desde patrones en HTML)
        # =====================================================
        
        if self.response:
            content = self.response.text.lower()
            
            # PostgreSQL (importante para Odoo)
            if ('postgresql' in content or 'pgsql' in content) and 'postgresql' not in detected:
                self.technologies.append(('postgresql', 'unknown'))
                detected.add('postgresql')
                console.print(f"   [green]✅ Detectado (HTML):[/green] postgresql")
                time.sleep(0.3)
            
            # MySQL
            if ('mysql' in content or 'mysqli' in content) and 'mysql' not in detected:
                self.technologies.append(('mysql', 'unknown'))
                detected.add('mysql')
                console.print(f"   [green]✅ Detectado (HTML):[/green] mysql")
                time.sleep(0.3)
            
            # MongoDB
            if 'mongodb' in content and 'mongodb' not in detected:
                self.technologies.append(('mongodb', 'unknown'))
                detected.add('mongodb')
                console.print(f"   [green]✅ Detectado (HTML):[/green] mongodb")
                time.sleep(0.3)

        # Mostrar resumen final
        if self.technologies:
            console.print(f"\n[bold green]📌 Tecnologías detectadas: {len(self.technologies)}[/bold green]")
            for tech, version in self.technologies:
                console.print(f"   • [cyan]{tech}[/cyan] [dim]versión {version}[/dim]")
        else:
            console.print("\n[yellow]⚠️  No se detectaron tecnologías específicas[/yellow]")
        
        time.sleep(1)  # Pausa final antes del resumen

    def _extract_wordpress_version(self, html):
        match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([0-9.]+)["\']', 
                         html, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _extract_odoo_version(self, html):
        match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']Odoo\s+([0-9.]+)["\']', 
                         html, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(r'Odoo\s+v?([0-9.]+)', html, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    # =====================================================
    # BÚSQUEDA DE CVEs
    # =====================================================

    def search_and_show_cves(self):
        """Busca CVEs y los muestra"""
        if not self.technologies:
            console.print("\n[yellow]⚠️  No hay tecnologías detectadas. Analiza una URL primero.[/yellow]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return

        console.clear()
        self.show_banner()

        console.print(Panel("[bold magenta]🔍 BÚSQUEDA DE CVEs[/bold magenta]", border_style="magenta"))

        console.print("\n[bold cyan]Tecnologías a analizar:[/bold cyan]")
        for tech, version in self.technologies:
            console.print(f"   • [cyan]{tech}[/cyan] [dim]versión {version}[/dim]")

        if not Confirm.ask("\n[bold]¿Quieres buscar CVEs para estas tecnologías?[/bold]"):
            return

        if not self.cve_db_loaded:
            console.print("[yellow]   Cargando base de datos de CVEs...[/yellow]")
            if self.cve_db.load_cves():
                self.cve_db_loaded = True
            else:
                console.print("[red]   ❌ Error cargando base de datos de CVEs[/red]")
                input("\n[dim]Presiona Enter para continuar...[/dim]")
                return

        self.cve_results = {}
        total_tech = len(self.technologies)
        current = 0

        console.print("\n[bold green]🔍 Buscando CVEs...[/bold green]")

        for tech, version in self.technologies:
            current += 1
            console.print(f"   [yellow]⌛ [{current}/{total_tech}] Revisando {tech} {version}...[/yellow]")
            
            with console.status(f"[bold green]   Buscando CVEs para {tech} {version}...[/bold green]"):
                cves = self.cve_db.search_cves_by_technology(tech, version)
                self.cve_results[f"{tech} {version}"] = {
                    'count': len(cves),
                    'cves': cves
                }
            
            if len(cves) > 0:
                console.print(f"   [green]✅ {tech} {version}: {len(cves)} CVEs encontrados[/green]")
            else:
                console.print(f"   [dim]ℹ️ {tech} {version}: 0 CVEs encontrados[/dim]")

        self.cves_searched = True

        console.print("\n[bold green]✅ Búsqueda completada[/bold green]")
        self.show_cves_detail()

    # =====================================================
    # VISUALIZACIÓN DE RESULTADOS
    # =====================================================

    def show_analysis_summary(self):
        """Muestra un resumen del análisis (sin CVEs)"""
        console.clear()
        self.show_banner()

        info_table = Table(show_header=False, box=box.SIMPLE)
        info_table.add_column("Métrica", style="bold cyan")
        info_table.add_column("Valor", style="white")

        info_table.add_row("🌐 URL", self.url)
        info_table.add_row("📊 Estado", f"{self.status_code} ({self.response.reason if self.response else 'N/A'})")
        info_table.add_row("⏱️  Tiempo", f"{self.response_time:.3f}s")
        info_table.add_row("🔒 HTTPS", "✅" if self.url.startswith('https') else "❌")
        info_table.add_row("📦 Tamaño", f"{len(self.response.content) if self.response else 0} bytes")

        console.print(Panel(info_table, title="[bold]📊 RESUMEN DEL ANÁLISIS[/bold]", border_style="green"))

        security_table = Table(show_header=False, box=box.SIMPLE)
        security_table.add_column("Componente", style="bold yellow")
        security_table.add_column("Estado", style="white")

        for check, value in self.security_checks.items():
            status = "✅" if value else "❌"
            security_table.add_row(check, status)

        if self.max_score > 0:
            percentage = (self.security_score / self.max_score) * 100
            color = "green" if percentage >= 70 else "yellow" if percentage >= 40 else "red"
            security_table.add_row(
                "🔒 Puntuación",
                f"[{color}]{percentage:.1f}% ({self.security_score}/{self.max_score})[/{color}]"
            )

        console.print(Panel(security_table, title="[bold]🔒 SEGURIDAD[/bold]", border_style="yellow"))

        if self.vulnerabilities:
            vuln_table = Table(show_header=True, box=box.SIMPLE)
            vuln_table.add_column("Severidad", style="bold")
            vuln_table.add_column("Tipo", style="cyan")
            vuln_table.add_column("Descripción", style="white")

            for vuln in self.vulnerabilities[:5]:
                severity = vuln['severity']
                color = "red" if severity == "Crítica" else "yellow" if severity == "Alta" else "blue"
                vuln_table.add_row(
                    f"[{color}]{severity}[/{color}]",
                    vuln['type'],
                    vuln['description'][:50] + ("..." if len(vuln['description']) > 50 else "")
                )

            if len(self.vulnerabilities) > 5:
                vuln_table.add_row("...", f"y {len(self.vulnerabilities) - 5} más", "")

            console.print(Panel(vuln_table, title="[bold]⚠️  VULNERABILIDADES[/bold]", border_style="red"))
        else:
            console.print(Panel("[bold green]✅ No se encontraron vulnerabilidades[/bold green]",
                              title="[bold]⚠️  VULNERABILIDADES[/bold]", border_style="green"))

        # Indicar que CVEs no se han buscado automáticamente
        if self.technologies:
            console.print(Panel(
                f"[yellow]💡 Se detectaron {len(self.technologies)} tecnologías.\n"
                f"   Usa la opción 5 del menú principal para buscar CVEs.[/yellow]",
                title="[bold]📌 CVEs[/bold]",
                border_style="yellow"
            ))
        else:
            console.print(Panel(
                "[yellow]⚠️  No se detectaron tecnologías para buscar CVEs[/yellow]",
                title="[bold]📌 CVEs[/bold]",
                border_style="yellow"
            ))

    def show_detailed_analysis(self):
        """Muestra el análisis detallado"""
        console.clear()
        self.show_banner()

        detail_menu = Table(show_header=False, box=box.ROUNDED)
        detail_menu.add_column("Opción", style="bold cyan", width=10)
        detail_menu.add_column("Descripción", style="white")

        detail_menu.add_row("1", "📋 Cabeceras HTTP completas")
        detail_menu.add_row("2", "🔒 Análisis detallado de seguridad")
        detail_menu.add_row("3", "⚠️  Vulnerabilidades con remediación")
        detail_menu.add_row("4", "📌 CVEs encontrados")
        detail_menu.add_row("5", "🍪 Análisis de cookies")
        detail_menu.add_row("6", "📊 Estadísticas de contenido")
        detail_menu.add_row("7", "↩️  Volver al menú principal")

        console.print(Panel(detail_menu, title="[bold]ANÁLISIS DETALLADO[/bold]", border_style="cyan"))

        choice = Prompt.ask("\n[bold cyan]Selecciona una opción[/bold cyan]",
                           choices=["1", "2", "3", "4", "5", "6", "7"])

        if choice == "1":
            self.show_headers_detail()
        elif choice == "2":
            self.show_security_detail()
        elif choice == "3":
            self.show_vulnerabilities_detail()
        elif choice == "4":
            self.show_cves_detail()
        elif choice == "5":
            self.show_cookies_detail()
        elif choice == "6":
            self.show_content_stats()
        elif choice == "7":
            return

    def show_headers_detail(self):
        console.clear()
        self.show_banner()
        console.print(Panel("[bold cyan]📋 CABECERAS HTTP[/bold cyan]", border_style="cyan"))

        if not self.classified_headers:
            console.print("[yellow]No hay cabeceras para mostrar[/yellow]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return

        for category, headers in self.classified_headers.items():
            if headers:
                table = Table(title=f"📌 {category}", box=box.ROUNDED)
                table.add_column("Cabecera", style="bold cyan")
                table.add_column("Valor", style="white")
                table.add_column("Significado", style="italic dim")

                for key, value in headers:
                    significance = self.get_header_significance(key, value)
                    table.add_row(key, value[:100] + ("..." if len(value) > 100 else ""), significance or "-")

                console.print(table)
                console.print()

        input("\n[dim]Presiona Enter para continuar...[/dim]")

    def get_header_significance(self, key, value):
        key_lower = key.lower()
        significance_map = {
            'server': f"Servidor web ({value})",
            'content-type': "Define el formato de los datos",
            'content-length': f"Tamaño del contenido: {value} bytes",
            'cache-control': f"Control de caché: {value}",
            'strict-transport-security': "HSTS - Forza conexiones HTTPS",
            'x-frame-options': "Protección contra clickjacking",
            'x-content-type-options': "Previene MIME sniffing",
            'x-xss-protection': "Protección contra XSS",
            'content-security-policy': "CSP - Política de seguridad de contenido",
            'content-encoding': f"Contenido comprimido: {value}"
        }
        for header, significance in significance_map.items():
            if header in key_lower:
                return significance
        return None

    def show_security_detail(self):
        console.clear()
        self.show_banner()
        console.print(Panel("[bold yellow]🔒 ANÁLISIS DE SEGURIDAD DETALLADO[/bold yellow]", border_style="yellow"))

        security_table = Table(box=box.ROUNDED)
        security_table.add_column("Elemento", style="bold cyan")
        security_table.add_column("Estado", style="bold")
        security_table.add_column("Descripción", style="white")
        security_table.add_column("Recomendación", style="italic dim")

        security_details = [
            ("HTTPS", self.security_checks.get('HTTPS', False), "Conexión segura", "Usar siempre HTTPS"),
            ("HSTS", self.security_checks.get('HSTS', False), "Forza HTTPS", "Configurar STS header"),
            ("X-Frame-Options", self.security_checks.get('X-Frame-Options', False), "Protección clickjacking", "Configurar DENY o SAMEORIGIN"),
            ("X-Content-Type-Options", self.security_checks.get('X-Content-Type-Options', False), "Previene MIME sniffing", "Configurar nosniff"),
            ("X-XSS-Protection", self.security_checks.get('X-XSS-Protection', False), "Protección XSS", "Configurar 1; mode=block"),
            ("CSP", self.security_checks.get('CSP', False), "Política de seguridad", "Implementar CSP"),
            ("Referrer-Policy", self.security_checks.get('Referrer-Policy', False), "Control de referer", "Configurar strict-origin-when-cross-origin")
        ]

        for element, status, desc, rec in security_details:
            status_text = "✅" if status else "❌"
            color = "green" if status else "red"
            security_table.add_row(element, f"[{color}]{status_text}[/{color}]", desc, rec)

        console.print(security_table)

        if self.max_score > 0:
            percentage = (self.security_score / self.max_score) * 100
            color = "green" if percentage >= 70 else "yellow" if percentage >= 40 else "red"
            console.print(Panel(
                f"[bold]Puntuación de seguridad:[/bold] [{color}]{percentage:.1f}%[/{color}]",
                border_style=color
            ))

        input("\n[dim]Presiona Enter para continuar...[/dim]")

    def show_vulnerabilities_detail(self):
        console.clear()
        self.show_banner()
        console.print(Panel("[bold red]⚠️  VULNERABILIDADES DETECTADAS[/bold red]", border_style="red"))

        if not self.vulnerabilities:
            console.print("[bold green]✅ No se encontraron vulnerabilidades[/bold green]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return

        for i, vuln in enumerate(self.vulnerabilities, 1):
            severity = vuln['severity']
            color = "red" if severity == "Crítica" else "yellow" if severity == "Alta" else "blue"

            vuln_panel = Panel(
                f"""[bold]Tipo:[/bold] {vuln['type']}
[bold]Severidad:[/bold] [{color}]{severity}[/{color}]
[bold]Descripción:[/bold] {vuln['description']}
[bold]Remediación:[/bold] {vuln.get('remediation', 'Consultar documentación de seguridad')}""",
                title=f"[bold red]Vulnerabilidad {i}[/bold red]",
                border_style=color
            )
            console.print(vuln_panel)
            console.print()

        input("\n[dim]Presiona Enter para continuar...[/dim]")

    def show_cves_detail(self):
        """Muestra CVEs encontrados con paginación mejorada"""
        console.clear()
        self.show_banner()
        
        # Mostrar resumen de tecnologías
        if self.technologies:
            console.print("\n[bold cyan]📌 Tecnologías analizadas:[/bold cyan]")
            tech_table = Table(box=box.SIMPLE)
            tech_table.add_column("Tecnología", style="cyan")
            tech_table.add_column("Versión", style="white")
            tech_table.add_column("CVEs Encontrados", style="bold yellow")
            tech_table.add_column("Críticos", style="bold red")
            tech_table.add_column("Altos", style="bold yellow")
            
            for tech, version in self.technologies:
                key = f"{tech} {version}"
                data = self.cve_results.get(key, {})
                cves = data.get('cves', [])
                critical = sum(1 for c in cves if c.get('severity', {}).get('severity') == 'CRITICAL')
                high = sum(1 for c in cves if c.get('severity', {}).get('severity') == 'HIGH')
                tech_table.add_row(
                    tech,
                    version,
                    str(len(cves)),
                    f"[red]{critical}[/red]",
                    f"[yellow]{high}[/yellow]"
                )
            console.print(Panel(tech_table, title="[bold]📊 RESUMEN DE CVEs POR TECNOLOGÍA[/bold]", border_style="magenta"))

        console.print(Panel("[bold magenta]📌 CVES ENCONTRADOS[/bold magenta]", border_style="magenta"))

        if not self.cve_results:
            console.print("[yellow]No hay CVEs para mostrar. Busca CVEs primero (opción 5).[/yellow]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return

        total_cves = sum(data['count'] for data in self.cve_results.values())

        if total_cves == 0:
            console.print("[bold green]✅ No se encontraron CVEs para las tecnologías detectadas[/bold green]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return

        # Mostrar CVEs por tecnología con paginación
        for tech_key, data in self.cve_results.items():
            if data['count'] == 0:
                continue

            # Extraer tecnología y versión para mostrar
            parts = tech_key.split(' ', 1)
            tech_name = parts[0] if parts else tech_key
            tech_version = parts[1] if len(parts) > 1 else ''

            console.print(f"\n[bold cyan]📌 {tech_name}[/bold cyan] [dim]versión {tech_version}[/dim]")
            console.print(f"   [bold]Total CVEs encontrados: {data['count']}[/bold]")

            sorted_cves = sorted(data['cves'],
                               key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}.get(
                                   x.get('severity', {}).get('severity', 'UNKNOWN'), 5))

            page_size = 10
            total_pages = (len(sorted_cves) + page_size - 1) // page_size
            current_page = 1

            while True:
                console.clear()
                self.show_banner()
                
                # Mostrar resumen de tecnologías en cada página
                if self.technologies:
                    console.print("\n[bold cyan]📌 Tecnologías analizadas:[/bold cyan]")
                    tech_table = Table(box=box.SIMPLE)
                    tech_table.add_column("Tecnología", style="cyan")
                    tech_table.add_column("Versión", style="white")
                    tech_table.add_column("CVEs Encontrados", style="bold yellow")
                    tech_table.add_column("Críticos", style="bold red")
                    tech_table.add_column("Altos", style="bold yellow")
                    
                    for tech, version in self.technologies:
                        key = f"{tech} {version}"
                        cves_data = self.cve_results.get(key, {})
                        cves_list = cves_data.get('cves', [])
                        critical = sum(1 for c in cves_list if c.get('severity', {}).get('severity') == 'CRITICAL')
                        high = sum(1 for c in cves_list if c.get('severity', {}).get('severity') == 'HIGH')
                        tech_table.add_row(
                            tech,
                            version,
                            str(len(cves_list)),
                            f"[red]{critical}[/red]",
                            f"[yellow]{high}[/yellow]"
                        )
                    console.print(Panel(tech_table, title="[bold]📊 RESUMEN DE CVEs POR TECNOLOGÍA[/bold]", border_style="magenta"))

                console.print(Panel(f"[bold magenta]📌 CVES ENCONTRADOS - {tech_name} {tech_version} (Página {current_page}/{total_pages})[/bold magenta]", border_style="magenta"))
                console.print(f"   [bold]Total CVEs: {len(sorted_cves)}[/bold]")

                start_idx = (current_page - 1) * page_size
                end_idx = min(start_idx + page_size, len(sorted_cves))
                page_cves = sorted_cves[start_idx:end_idx]

                cve_table = Table(box=box.ROUNDED)
                cve_table.add_column("#", style="dim", width=4)
                cve_table.add_column("CVE ID", style="bold red", width=16)
                cve_table.add_column("Severidad", style="bold", width=12)
                cve_table.add_column("Puntuación", style="bold", width=10)
                cve_table.add_column("Descripción", style="white", max_width=60)

                for idx, cve in enumerate(page_cves, start_idx + 1):
                    severity = cve.get('severity', {})
                    sev = severity.get('severity', 'UNKNOWN')
                    score = severity.get('score', 'N/A')

                    color = "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "blue" if sev == "MEDIUM" else "green"

                    desc = "No disponible"
                    for d in cve.get('descriptions', []):
                        if d.get('lang') == 'en':
                            desc = d.get('value', '')[:80] + "..." if len(d.get('value', '')) > 80 else d.get('value', '')
                            break

                    cve_table.add_row(
                        str(idx),
                        cve.get('id', 'Unknown'),
                        f"[{color}]{sev}[/{color}]",
                        str(score),
                        desc
                    )

                console.print(cve_table)

                # Información de paginación mejorada
                console.print(f"\n[dim]📄 Página {current_page} de {total_pages} | Mostrando CVEs {start_idx + 1}-{end_idx} de {len(sorted_cves)}[/dim]")
                
                # Controles de paginación mejorados
                console.print("\n[bold]🔄 Controles de navegación:[/bold]")
                controls = []
                if current_page > 1:
                    controls.append("[p] Página anterior")
                if current_page < total_pages:
                    controls.append("[n] Siguiente página")
                controls.append("[f] Primera página")
                controls.append("[l] Última página")
                controls.append("[q] Volver al menú")
                controls.append("[Enter] Salir de esta tecnología")
                
                console.print("   " + " | ".join(controls))

                choice = Prompt.ask("\n[bold cyan]Opción[/bold cyan]", default="q")
                choice = choice.lower().strip()

                if choice == 'n' and current_page < total_pages:
                    current_page += 1
                elif choice == 'p' and current_page > 1:
                    current_page -= 1
                elif choice == 'f':
                    current_page = 1
                elif choice == 'l':
                    current_page = total_pages
                elif choice == 'q' or choice == '':
                    break
                else:
                    console.print("[red]❌ Opción no válida[/red]")
                    time.sleep(0.5)

        input("\n[dim]Presiona Enter para volver al menú principal...[/dim]")

    def show_cookies_detail(self):
        console.clear()
        self.show_banner()
        console.print(Panel("[bold cyan]🍪 ANÁLISIS DE COOKIES[/bold cyan]", border_style="cyan"))

        if not self.response or not self.response.cookies:
            console.print("[yellow]No se encontraron cookies[/yellow]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return

        cookie_table = Table(box=box.ROUNDED)
        cookie_table.add_column("Nombre", style="bold cyan")
        cookie_table.add_column("Valor", style="white")
        cookie_table.add_column("Secure", style="bold")
        cookie_table.add_column("HttpOnly", style="bold")
        cookie_table.add_column("Dominio", style="dim")
        cookie_table.add_column("Ruta", style="dim")

        for cookie in self.response.cookies:
            secure = "✅" if cookie.secure else "❌"
            httponly = "✅" if cookie.has_nonstandard_attr('httponly') else "❌"
            cookie_table.add_row(
                cookie.name,
                cookie.value[:30] + ("..." if len(cookie.value) > 30 else ""),
                secure,
                httponly,
                cookie.domain or "-",
                cookie.path or "/"
            )

        console.print(cookie_table)

        secure_count = sum(1 for c in self.response.cookies if c.secure)
        httponly_count = sum(1 for c in self.response.cookies if c.has_nonstandard_attr('httponly'))
        total = len(self.response.cookies)

        if total > 0:
            summary = f"""
[bold]Resumen de seguridad:[/bold]
• Cookies totales: {total}
• Con Secure: {secure_count}/{total} ({secure_count/total*100:.1f}%)
• Con HttpOnly: {httponly_count}/{total} ({httponly_count/total*100:.1f}%)
            """
            console.print(Panel(summary, border_style="yellow"))

        input("\n[dim]Presiona Enter para continuar...[/dim]")

    def show_content_stats(self):
        console.clear()
        self.show_banner()
        console.print(Panel("[bold green]📊 ESTADÍSTICAS DE CONTENIDO[/bold green]", border_style="green"))

        if not self.response:
            console.print("[red]No hay contenido para analizar[/red]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return

        content = self.response.text
        content_type = self.response.headers.get('content-type', '')

        stats = {
            "Tamaño total": f"{len(self.response.content)} bytes",
            "Tamaño texto": f"{len(content)} caracteres",
            "Tipo de contenido": content_type,
            "Líneas": len(content.split('\n')),
            "Palabras": len(content.split()),
            "Caracteres": len(content)
        }

        if 'html' in content_type.lower():
            links = len(re.findall(r'<link[^>]*>', content, re.IGNORECASE))
            scripts = len(re.findall(r'<script[^>]*>', content, re.IGNORECASE))
            images = len(re.findall(r'<img[^>]*>', content, re.IGNORECASE))
            forms = len(re.findall(r'<form[^>]*>', content, re.IGNORECASE))

            stats.update({
                "Enlaces CSS": links,
                "Scripts JS": scripts,
                "Imágenes": images,
                "Formularios": forms
            })

            title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
            if title_match:
                stats["Título"] = title_match.group(1)

        stat_table = Table(box=box.ROUNDED)
        stat_table.add_column("Métrica", style="bold cyan")
        stat_table.add_column("Valor", style="white")

        for key, value in stats.items():
            stat_table.add_row(key, str(value))

        console.print(stat_table)

        input("\n[dim]Presiona Enter para continuar...[/dim]")

    def generate_report(self):
        console.clear()
        self.show_banner()
        console.print(Panel("[bold green]📊 GENERANDO REPORTE[/bold green]", border_style="green"))

        if not self.url:
            console.print("[red]❌ No hay análisis realizado. Analiza una URL primero.[/red]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return

        report = {
            'url': self.url,
            'timestamp': datetime.now().isoformat(),
            'status': self.status_code,
            'headers': self.headers,
            'security_checks': self.security_checks,
            'vulnerabilities': self.vulnerabilities,
            'score': f"{self.security_score}/{self.max_score}",
            'technologies': self.technologies,
            'cves': self.cve_results
        }

        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        console.print(f"[bold green]✅ Reporte guardado como: {filename}[/bold green]")

        console.print(Panel(
            f"""
[bold]URL:[/bold] {report['url']}
[bold]Estado:[/bold] {report['status']}
[bold]Fecha:[/bold] {report['timestamp']}
[bold]Vulnerabilidades:[/bold] {len(report['vulnerabilities'])}
[bold]Tecnologías detectadas:[/bold] {len(report['technologies'])}
[bold]CVEs encontrados:[/bold] {sum(data['count'] for data in report['cves'].values()) if report['cves'] else 0}
[bold]Puntuación:[/bold] {report['score']}
            """,
            title="[bold]RESUMEN DEL REPORTE[/bold]",
            border_style="green"
        ))

        input("\n[dim]Presiona Enter para continuar...[/dim]")


def main():
    try:
        analyzer = WebSecurityAnalyzer()
        analyzer.run()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Programa interrumpido por el usuario[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")
        import traceback
        console.print(traceback.format_exc())


if __name__ == "__main__":
    main()
