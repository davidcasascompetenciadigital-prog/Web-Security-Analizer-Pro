#!/usr/bin/env python3
"""
Web Security Analyzer Pro - Versión Interactiva con Interfaz Visual
Análisis completo de cabeceras, datos y vulnerabilidades con presentación visual

Autor: David Casas M. - Competencia Digital
Licencia: CC BY-NC 4.0
"""

import requests
import json
import time
import ssl
import socket
import re
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional
import warnings
warnings.filterwarnings('ignore')

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
    import subprocess
    subprocess.check_call(['pip', 'install', 'rich'])
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich import box
    RICH_AVAILABLE = True

console = Console()

class VisualWebAnalyzer:
    """Analizador web con interfaz visual interactiva"""
    
    def __init__(self):
        self.url = None
        self.session = requests.Session()
        self.results = {}
        self.vulnerabilities = []
        self.cves_found = []
        self.security_score = 0
        self.max_score = 0
        self.start_time = None
        self.response = None
        self.headers = {}
        self.classified_headers = {}
        self.security_checks = {}
        self.url_info = {}
        self.status_code = None
        self.response_time = 0
        self.final_url = None
        
    def run(self):
        """Ejecuta el programa interactivo"""
        self.show_banner()
        
        while True:
            self.show_main_menu()
            choice = Prompt.ask(
                "\n[bold cyan]Selecciona una opción[/bold cyan]",
                choices=["1", "2", "3", "4", "5", "6", "7"],
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
                self.show_cves_detail()
            elif choice == "6":
                self.generate_report()
            elif choice == "7":
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
║                    🔍 Análisis Web de Seguridad Pro                          ║
║                   Interactive Security Scanner v2.0                         ║
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
        menu.add_row("5", "📌 CVEs detectados")
        menu.add_row("6", "📊 Generar reporte")
        menu.add_row("7", "🚪 Salir")
        
        console.print(Panel(menu, title="[bold]MENÚ PRINCIPAL[/bold]", border_style="cyan"))
    
    def analyze_website(self):
        """Analiza una URL ingresada por el usuario"""
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
            
            task1 = progress.add_task("[cyan]Conectando...", total=100)
            progress.update(task1, advance=20)
            time.sleep(0.3)
            
            # Realizar análisis
            self.analyze_url()
            progress.update(task1, advance=40)
            time.sleep(0.3)
            
            self.response = self.make_request()
            progress.update(task1, advance=60)
            time.sleep(0.3)
            
            if self.response:
                self.analyze_headers(self.response)
                progress.update(task1, advance=80)
                time.sleep(0.3)
                
                self.analyze_security(self.response)
                progress.update(task1, advance=90)
                time.sleep(0.3)
                
                self.analyze_vulnerabilities()
                progress.update(task1, advance=100)
                time.sleep(0.5)
        
        # Mostrar resumen del análisis
        self.show_analysis_summary()
        
        # Preguntar si quiere ver detalles
        if Confirm.ask("\n[bold]¿Quieres ver el análisis detallado?[/bold]"):
            self.show_detailed_analysis()
    
    def analyze_url(self):
        """Analiza la estructura de la URL"""
        parsed = urlparse(self.url)
        self.url_info = {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path or '/',
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment
        }
    
    def make_request(self):
        """Realiza la petición HTTP"""
        try:
            self.start_time = time.time()
            response = self.session.get(
                self.url, 
                timeout=10, 
                allow_redirects=True,
                headers={'User-Agent': 'WebSecurityAnalyzer/2.0'}
            )
            self.response_time = time.time() - self.start_time
            self.status_code = response.status_code
            self.final_url = response.url
            return response
        except Exception as e:
            console.print(f"[red]❌ Error: {str(e)}[/red]")
            return None
    
    def analyze_headers(self, response):
        """Analiza las cabeceras HTTP"""
        self.headers = dict(response.headers)
        
        # Clasificar cabeceras
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
            'CSP': 'content-security-policy' in response.headers
        }
        
        # Calcular puntuación de seguridad
        self.security_score = sum(1 for v in self.security_checks.values() if v)
        self.max_score = len(self.security_checks)
    
    def analyze_vulnerabilities(self):
        """Análisis de vulnerabilidades"""
        self.vulnerabilities = []
        
        # Verificar cabeceras de seguridad faltantes
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
        
        # Verificar información del servidor expuesta
        if 'server' in self.headers:
            self.vulnerabilities.append({
                'type': 'Información del servidor expuesta',
                'severity': 'Baja',
                'description': f'Servidor: {self.headers["server"]}',
                'remediation': 'Ocultar información del servidor en la configuración'
            })
        
        # Verificar cookies inseguras
        if self.response and self.response.cookies:
            for cookie in self.response.cookies:
                # Ignorar cookies que Odoo maneja correctamente
                if cookie.name in ['frontend_lang', 'visitor_uuid', 'session_id']:
                    continue
                    
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
    
    def show_analysis_summary(self):
        """Muestra un resumen del análisis"""
        console.clear()
        self.show_banner()
        
        # Panel de información general
        info_table = Table(show_header=False, box=box.SIMPLE)
        info_table.add_column("Métrica", style="bold cyan")
        info_table.add_column("Valor", style="white")
        
        info_table.add_row("🌐 URL", self.url)
        info_table.add_row("📊 Estado", f"{self.status_code} ({self.response.reason if self.response else 'N/A'})")
        info_table.add_row("⏱️  Tiempo", f"{self.response_time:.3f}s" if hasattr(self, 'response_time') else "N/A")
        info_table.add_row("🔒 HTTPS", "✅" if self.url.startswith('https') else "❌")
        info_table.add_row("📦 Tamaño", f"{len(self.response.content) if self.response else 0} bytes")
        info_table.add_row("🔄 Redirecciones", str(len(self.response.history) if self.response else 0))
        
        console.print(Panel(info_table, title="[bold]📊 RESUMEN DEL ANÁLISIS[/bold]", border_style="green"))
        
        # Panel de seguridad
        security_table = Table(show_header=False, box=box.SIMPLE)
        security_table.add_column("Componente", style="bold yellow")
        security_table.add_column("Estado", style="white")
        
        for check, value in self.security_checks.items():
            status = "✅" if value else "❌"
            security_table.add_row(check, status)
        
        # Calcular porcentaje
        if self.max_score > 0:
            percentage = (self.security_score / self.max_score) * 100
            color = "green" if percentage >= 70 else "yellow" if percentage >= 40 else "red"
            security_table.add_row(
                "🔒 Puntuación", 
                f"[{color}]{percentage:.1f}% ({self.security_score}/{self.max_score})[/{color}]"
            )
        
        console.print(Panel(security_table, title="[bold]🔒 SEGURIDAD[/bold]", border_style="yellow"))
        
        # Panel de vulnerabilidades
        if self.vulnerabilities:
            vuln_table = Table(show_header=True, box=box.SIMPLE)
            vuln_table.add_column("Severidad", style="bold")
            vuln_table.add_column("Tipo", style="cyan")
            vuln_table.add_column("Descripción", style="white")
            
            for vuln in self.vulnerabilities[:5]:
                severity = vuln['severity']
                color = "red" if severity == "Crítica" else "yellow" if severity == "Alta" else "blue" if severity == "Media" else "green"
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
    
    def show_detailed_analysis(self):
        """Muestra el análisis detallado en formato interactivo"""
        console.clear()
        self.show_banner()
        
        detail_menu = Table(show_header=False, box=box.ROUNDED)
        detail_menu.add_column("Opción", style="bold cyan", width=10)
        detail_menu.add_column("Descripción", style="white")
        
        detail_menu.add_row("1", "📋 Cabeceras HTTP completas")
        detail_menu.add_row("2", "🔒 Análisis detallado de seguridad")
        detail_menu.add_row("3", "⚠️  Vulnerabilidades con remediación")
        detail_menu.add_row("4", "📌 CVEs y tecnologías")
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
        """Muestra las cabeceras en detalle"""
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
        """Obtiene el significado de una cabecera"""
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
        """Muestra análisis detallado de seguridad"""
        console.clear()
        self.show_banner()
        
        console.print(Panel("[bold yellow]🔒 ANÁLISIS DE SEGURIDAD DETALLADO[/bold yellow]", border_style="yellow"))
        
        if not self.security_checks:
            console.print("[yellow]No hay datos de seguridad para mostrar[/yellow]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return
        
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
            ("CSP", self.security_checks.get('CSP', False), "Política de seguridad", "Implementar CSP"),
            ("X-XSS-Protection", self.security_checks.get('X-XSS-Protection', False), "Protección XSS", "Configurar 1; mode=block")
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
        """Muestra vulnerabilidades con remediación"""
        console.clear()
        self.show_banner()
        
        console.print(Panel("[bold red]⚠️  VULNERABILIDADES DETECTADAS[/bold red]", border_style="red"))
        
        if not self.vulnerabilities:
            console.print("[bold green]✅ No se encontraron vulnerabilidades[/bold green]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            severity = vuln['severity']
            color = "red" if severity == "Crítica" else "yellow" if severity == "Alta" else "blue" if severity == "Media" else "green"
            
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
        """Muestra CVEs detectados"""
        console.clear()
        self.show_banner()
        
        console.print(Panel("[bold magenta]📌 CVES DETECTADOS[/bold magenta]", border_style="magenta"))
        
        technologies = []
        if 'server' in self.headers:
            technologies.append(f"Servidor: {self.headers['server']}")
        if self.response and 'x-powered-by' in self.response.headers:
            technologies.append(f"Framework: {self.response.headers['x-powered-by']}")
        
        if technologies:
            tech_table = Table(title="Tecnologías Detectadas", box=box.ROUNDED)
            tech_table.add_column("Tecnología", style="cyan")
            tech_table.add_column("Versión", style="white")
            
            for tech in technologies:
                tech_table.add_row(tech, "No especificada")
            
            console.print(tech_table)
            console.print()
            
            console.print("[bold yellow]CVEs potenciales (simulación):[/bold yellow]")
            cve_table = Table(box=box.ROUNDED)
            cve_table.add_column("CVE", style="bold red")
            cve_table.add_column("Tecnología", style="cyan")
            cve_table.add_column("Descripción", style="white")
            cve_table.add_column("Severidad", style="bold")
            
            sample_cves = [
                ("CVE-2021-23017", "nginx", "Buffer Overflow", "Alta"),
                ("CVE-2021-39275", "Apache", "Denial of Service", "Media"),
                ("CVE-2021-29447", "WordPress", "XSS", "Media")
            ]
            
            for cve_id, tech, desc, severity in sample_cves:
                color = "red" if severity == "Alta" else "yellow"
                cve_table.add_row(cve_id, tech, desc, f"[{color}]{severity}[/{color}]")
            
            console.print(cve_table)
            console.print()
            
            console.print("[italic dim]Nota: Los CVEs mostrados son simulados. En producción usar NVD API.[/italic dim]")
        else:
            console.print("[yellow]No se detectaron tecnologías específicas para buscar CVEs[/yellow]")
        
        input("\n[dim]Presiona Enter para continuar...[/dim]")
    
    def show_cookies_detail(self):
        """Muestra análisis de cookies"""
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
        """Muestra estadísticas de contenido"""
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
        
        if len(content) > 0:
            screen_size = len(content) / 3000
            console.print(Panel(
                f"[bold]Tamaño estimado en pantalla:[/bold] {screen_size:.1f} pantallas",
                border_style="dim"
            ))
        
        input("\n[dim]Presiona Enter para continuar...[/dim]")
    
    def generate_report(self):
        """Genera un reporte completo"""
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
            'status': self.status_code if hasattr(self, 'status_code') else None,
            'headers': self.headers if hasattr(self, 'headers') else {},
            'security_checks': self.security_checks if hasattr(self, 'security_checks') else {},
            'vulnerabilities': self.vulnerabilities,
            'score': f"{self.security_score}/{self.max_score}" if hasattr(self, 'security_score') else "N/A"
        }
        
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        console.print(f"[bold green]✅ Reporte guardado como: {filename}[/bold green]")
        
        console.print(Panel(
            f"""
[bold]URL:[/bold] {report['url']}
[bold]Estado:[/bold] {report['status']}
[bold]Fecha:[/bold] {report['timestamp']}
[bold]Vulnerabilidades:[/bold] {len(report['vulnerabilities'])}
[bold]Puntuación:[/bold] {report['score']}
            """,
            title="[bold]RESUMEN DEL REPORTE[/bold]",
            border_style="green"
        ))
        
        input("\n[dim]Presiona Enter para continuar...[/dim]")


def main():
    """Función principal"""
    try:
        analyzer = VisualWebAnalyzer()
        analyzer.run()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Programa interrumpido por el usuario[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")
        import traceback
        console.print(traceback.format_exc())

if __name__ == "__main__":
    main()
