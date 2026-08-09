#!/usr/bin/env python3
"""
Web Security Analyzer Pro - Versión Interactiva con Interfaz Visual
Análisis completo de cabeceras, datos y vulnerabilidades con presentación visual

Autor: David Casas M. - Competencia Digital
Licencia: CC BY-NC 4.0
"""

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

import requests

# Librerías para interfaz visual
try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    print("Error: 'rich' is required for the interactive UI.")
    print("Install it with: pip install rich")
    sys.exit(1)

console = Console()

# ===== Configuración NVD (National Vulnerability Database) =====
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_CACHE_DIR = '.cache'
NVD_CACHE_FILE = 'nvd_cves.json'
NVD_REQUEST_INTERVAL = 6.0
NVD_RATE_LIMIT_WAIT = 30.0
NVD_TIMEOUT = 15

# Mapa de tecnologías detectadas -> (vendor, product) del CPE 2.3
CPE_MAP = {
    'nginx': ('nginx', 'nginx'),
    'apache': ('apache', 'http_server'),
    'php': ('php', 'php'),
    'asp.net': ('microsoft', 'asp_net_core'),
    'wordpress': ('wordpress', 'wordpress'),
}

VERSION_REGEX = re.compile(r'\d+(?:\.\d+){1,3}')


def cookie_has_attr(cookie, attr_name, response):
    """Detecta un atributo de cookie de forma insensible a mayúsculas.

    - Escanea cookie._rest (http.cookiejar conserva la capitalización
      original, p.ej. 'HttpOnly').
    - Fallback: busca el atributo en las cabeceras Set-Cookie crudas con
      regex de límite de palabra (IGNORECASE).
    """
    attr = attr_name.lower()
    for key in getattr(cookie, '_rest', {}):
        if str(key).lower() == attr:
            return True
    if response is not None:
        raw_values = []
        headers = getattr(response, 'headers', None)
        if headers is not None:
            getlist = getattr(headers, 'getlist', None)
            if getlist is not None:
                raw_values.extend(getlist('Set-Cookie'))
            else:
                single = headers.get('Set-Cookie')
                if single:
                    raw_values.append(single)
        raw_headers = getattr(getattr(response, 'raw', None), 'headers', None)
        if raw_headers is not None:
            getlist = getattr(raw_headers, 'getlist', None)
            if getlist is not None:
                raw_values.extend(getlist('Set-Cookie'))
        for raw in raw_values:
            if raw and re.search(r'\b' + re.escape(attr_name) + r'\b', raw, re.IGNORECASE):
                return True
    return False


def build_cpe(vendor, product, version):
    """Construye un identificador CPE 2.3 para consultar NVD."""
    return f'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'


def extract_version(text):
    """Extrae la primera versión numérica (p.ej. 1.18.0) de un texto."""
    if not text:
        return None
    match = VERSION_REGEX.search(text)
    return match.group(0) if match else None


def detect_technologies(response, html):
    """Detecta tecnologías (name/vendor/product/version) desde cabeceras y meta generator."""
    techs = []
    seen = set()
    headers = getattr(response, 'headers', {}) or {}

    candidates = []
    if 'server' in headers:
        candidates.append(headers['server'])
    if 'x-powered-by' in headers:
        candidates.append(headers['x-powered-by'])
    if html:
        meta = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if meta:
            candidates.append(meta.group(1))

    for text in candidates:
        text_lower = text.lower()
        for tech, (vendor, product) in CPE_MAP.items():
            if tech in text_lower and tech not in seen:
                seen.add(tech)
                techs.append({
                    'name': tech,
                    'vendor': vendor,
                    'product': product,
                    'version': extract_version(text),
                })
                break
    return techs


def load_nvd_cache(path):
    """Carga el caché NVD. Ante corrupción devuelve un diccionario vacío."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get('schema_version') == 1:
            return data
        return {}
    except (OSError, ValueError):
        return {}


def save_nvd_cache(path, data):
    """Persiste el caché NVD (write-through)."""
    try:
        dirname = os.path.dirname(path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


def _nvd_fetch(cpe, last_request_time):
    """Consulta la API NVD 2.0 por un CPE con paginación. Devuelve (cves, nuevo_last_request_time)."""
    params = {'cpeName': cpe, 'resultsPerPage': 100}
    cves = []
    try:
        for page in range(5):
            now = time.time()
            wait = NVD_REQUEST_INTERVAL - (now - last_request_time)
            if wait > 0:
                time.sleep(wait)

            resp = requests.get(NVD_API_URL, params=params, timeout=NVD_TIMEOUT)
            last_request_time = time.time()
            if resp.status_code == 403:
                time.sleep(NVD_RATE_LIMIT_WAIT)
                resp = requests.get(NVD_API_URL, params=params, timeout=NVD_TIMEOUT)
                last_request_time = time.time()
            if resp.status_code != 200:
                return cves, last_request_time
            data = resp.json()
            total_results = data.get('totalResults', 0)
            vulnerabilities = data.get('vulnerabilities', [])
            for item in vulnerabilities:
                cve = item.get('cve', {})
                cve_id = cve.get('id', '')
                if not cve_id:
                    continue
                metrics = cve.get('metrics', {})
                entry = (metrics.get('cvssMetricV31')
                         or metrics.get('cvssMetricV30')
                         or metrics.get('cvssMetricV2') or [{}])[0]
                cvss_data = entry.get('cvssData', {})
                score = cvss_data.get('baseScore')
                severity = (entry.get('baseSeverity')
                            or cvss_data.get('baseSeverity') or 'DESCONOCIDA').upper()
                summary = ''
                for desc in cve.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        summary = desc.get('value', '')
                        break
                cves.append({
                    'id': cve_id,
                    'severity': severity,
                    'score': score,
                    'summary': summary,
                    'published': cve.get('published', ''),
                    'url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                })
            if len(cves) >= total_results or len(vulnerabilities) == 0:
                break
            params['startIndex'] = (params.get('startIndex', 0) + 100)
        return cves, last_request_time
    except requests.exceptions.RequestException:
        return cves, last_request_time
    except ValueError:
        return cves, last_request_time


def lookup_cves(tech_list, cache_path, last_request_time):
    """Orquesta la consulta NVD por tecnología con caché y throttling.

    Devuelve (resultado, nuevo_last_request_time). resultado: dict
    { 'tecnologia': { 'cpe', 'source': 'nvd'|'cache', 'cves': [...] } }.
    Ante fallo de red sin caché, cves queda vacío (nunca se fabrican datos).
    """
    result = {}
    cache = load_nvd_cache(cache_path)
    entries = cache.setdefault('entries', {})

    for tech in tech_list:
        name = tech.get('name', '')
        vendor = tech.get('vendor', '')
        product = tech.get('product', '')
        version = tech.get('version')
        if not version:
            result[name] = {'cpe': None, 'source': None, 'cves': []}
            continue

        key = f'{vendor}:{product}:{version}'
        cpe = build_cpe(vendor, product, version)

        if key in entries:
            result[name] = {'cpe': cpe, 'source': 'cache', 'cves': entries[key].get('cves', [])}
            continue

        cves, last_request_time = _nvd_fetch(cpe, last_request_time)

        if cves:
            entries[key] = {
                'source': 'nvd',
                'fetched_at': datetime.now().isoformat(),
                'cves': cves,
            }
            save_nvd_cache(cache_path, cache)
            result[name] = {'cpe': cpe, 'source': 'nvd', 'cves': cves}
        else:
            result[name] = {'cpe': cpe, 'source': None, 'cves': []}

    return result, last_request_time


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
        self.html = None
        self.security_checks = {}
        self.url_info = {}
        self.status_code = None
        self.response_time = 0
        self.final_url = None
        # Configuración NVD
        self.cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), NVD_CACHE_DIR, NVD_CACHE_FILE)
        self.cve_lookup = {}
        self.last_nvd_request = 0.0
        
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
                self.url or '', 
                timeout=10, 
                allow_redirects=True,
                headers={'User-Agent': 'WebSecurityAnalyzer/2.0'}
            )
            self.response_time = time.time() - self.start_time
            self.status_code = response.status_code
            self.final_url = response.url
            self.html = response.text
            return response
        except Exception as e:
            console.print(f"[red]❌ Error: {e!s}[/red]")
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
            'HTTPS': (self.url or '').startswith('https'),
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
                    
                if not cookie.secure and (self.url or '').startswith('https'):
                    self.vulnerabilities.append({
                        'type': f'Cookie {cookie.name} sin Secure',
                        'severity': 'Media',
                        'description': f'Cookie {cookie.name} no tiene flag Secure',
                        'remediation': 'Agregar flag Secure a la cookie'
                    })
                if not cookie_has_attr(cookie, 'httponly', self.response):
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
        info_table.add_row("🔒 HTTPS", "✅" if (self.url or '').startswith('https') else "❌")
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
        """Muestra CVEs reales detectados vía NVD API"""
        console.clear()
        self.show_banner()
        
        console.print(Panel("[bold magenta]📌 CVES DETECTADOS[/bold magenta]", border_style="magenta"))
        
        technologies = detect_technologies(self.response, self.html)
        
        if not technologies:
            console.print("[yellow]No se detectaron tecnologías específicas para buscar CVEs[/yellow]")
            input("\n[dim]Presiona Enter para continuar...[/dim]")
            return
        
        tech_table = Table(title="Tecnologías Detectadas", box=box.ROUNDED)
        tech_table.add_column("Tecnología", style="cyan")
        tech_table.add_column("Versión", style="white")
        
        for tech in technologies:
            tech_table.add_row(tech['name'], tech.get('version') or "No especificada")
        
        console.print(tech_table)
        console.print()
        
        result, self.last_nvd_request = lookup_cves(
            technologies, self.cache_path, self.last_nvd_request
        )
        self.cve_lookup = result
        
        console.print("[bold yellow]CVEs (datos reales de NVD):[/bold yellow]")
        cve_table = Table(box=box.ROUNDED)
        cve_table.add_column("CVE", style="bold red")
        cve_table.add_column("Tecnología", style="cyan")
        cve_table.add_column("Score", style="bold")
        cve_table.add_column("Severidad", style="bold")
        cve_table.add_column("Descripción", style="white")
        cve_table.add_column("Fuente", style="dim")
        
        found_any = False
        for tech in technologies:
            entry = result.get(tech['name'])
            if not entry or not entry.get('cves'):
                continue
            found_any = True
            source = entry.get('source') or 'nvd'
            source_label = "caché" if source == 'cache' else "NVD"
            for cve in entry['cves']:
                severity = cve.get('severity') or 'DESCONOCIDA'
                sev_lower = severity.lower()
                color = "red" if sev_lower in ('critical', 'high', 'alta', 'alta') else ("yellow" if sev_lower in ('medium', 'media') else "green")
                score = cve.get('score')
                score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "N/A"
                summary = (cve.get('summary') or '')[:90]
                cve_table.add_row(
                    cve.get('id', '-'), tech['name'], score_str,
                    f"[{color}]{severity}[/{color}]", summary, source_label
                )
        
        if not found_any:
            console.print("[green]No se encontraron CVEs para las tecnologías detectadas.[/green]")
            console.print()
            for tech in technologies:
                entry = result.get(tech['name'])
                if entry and entry.get('cpe'):
                    console.print(f"  [dim]{tech['name']}: {entry['cpe']} — sin CVEs publicados[/dim]")
                elif entry:
                    console.print(f"  [dim]{tech['name']}: versión no detectable, no se consultó NVD[/dim]")
        else:
            console.print(cve_table)
        
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
            httponly = "✅" if cookie_has_attr(cookie, 'httponly', self.response) else "❌"
            cookie_table.add_row(
                cookie.name,
                (cookie.value or '')[:30] + ("..." if len(cookie.value or '') > 30 else ""),
                secure,
                httponly,
                cookie.domain or "-",
                cookie.path or "/"
            )
        
        console.print(cookie_table)
        
        secure_count = sum(1 for c in self.response.cookies if c.secure)
        httponly_count = sum(1 for c in self.response.cookies if cookie_has_attr(c, 'httponly', self.response))
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
    
    def generate_report(self, interactive=True):
        """Genera un reporte completo. Con interactive=False omite el modo visual (CLI no interactivo)."""
        if interactive:
            console.clear()
            self.show_banner()
        
        console.print(Panel("[bold green]📊 GENERANDO REPORTE[/bold green]", border_style="green"))
        
        if not self.url:
            console.print("[red]❌ No hay análisis realizado. Analiza una URL primero.[/red]")
            if interactive:
                input("\n[dim]Presiona Enter para continuar...[/dim]")
            return
        
        # Cookies: nombre, flags (Secure/HttpOnly/SameSite)
        cookies = []
        if self.response and self.response.cookies:
            for c in self.response.cookies:
                cookies.append({
                    'name': c.name,
                    'value': c.value,
                    'secure': c.secure,
                    'httponly': cookie_has_attr(c, 'httponly', self.response),
                    'samesite': cookie_has_attr(c, 'samesite', self.response),
                    'domain': c.domain,
                    'path': c.path,
                })
        
        # CVEs: agregar los resultados reales de NVD
        cves = []
        for tech, entry in (self.cve_lookup or {}).items():
            for cve in entry.get('cves', []):
                cves.append({
                    'id': cve.get('id'),
                    'technology': tech,
                    'severity': cve.get('severity'),
                    'score': cve.get('score'),
                    'summary': cve.get('summary'),
                    'url': cve.get('url'),
                })
        
        report = {
            'url': self.url,
            'timestamp': datetime.now().isoformat(),
            'status': self.status_code if hasattr(self, 'status_code') else None,
            'final_url': self.final_url if hasattr(self, 'final_url') else None,
            'redirects': len(self.response.history) if (hasattr(self, 'response') and self.response and hasattr(self.response, 'history')) else 0,
            'headers': self.headers if hasattr(self, 'headers') else {},
            'security_checks': self.security_checks if hasattr(self, 'security_checks') else {},
            'vulnerabilities': self.vulnerabilities,
            'cookies': cookies,
            'cves': cves,
            'score': f"{self.security_score}/{self.max_score}" if hasattr(self, 'security_score') else "N/A"
        }
        
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        console.print(f"[bold green]✅ Reporte guardado como: {filename}[/bold green]")
        
        if not interactive:
            return
        
        console.print(Panel(
            f"""
[bold]URL:[/bold] {report['url']}
[bold]Estado:[/bold] {report['status']}
[bold]Fecha:[/bold] {report['timestamp']}
[bold]Vulnerabilidades:[/bold] {len(report['vulnerabilities'])}
[bold]Cookies:[/bold] {len(report['cookies'])}
[bold]CVEs:[/bold] {len(report['cves'])}
[bold]Puntuación:[/bold] {report['score']}
            """,
            title="[bold]RESUMEN DEL REPORTE[/bold]",
            border_style="green"
        ))
        
        input("\n[dim]Presiona Enter para continuar...[/dim]")


def main():
    """Función principal: modo interactivo o análisis por CLI con --url"""
    parser = argparse.ArgumentParser(
        description='Web Security Analyzer Pro: análisis de cabeceras, vulnerabilidades y CVEs (NVD)'
    )
    parser.add_argument(
        '-u', '--url', metavar='URL',
        help='URL a analizar en modo no interactivo (genera reporte JSON y termina)'
    )
    args = parser.parse_args()

    analyzer = VisualWebAnalyzer()

    try:
        if args.url:
            # ---- Modo no interactivo (CLI) ----
            analyzer.url = args.url.strip()
            if not analyzer.url.startswith(('http://', 'https://')):
                analyzer.url = 'https://' + analyzer.url

            console.print(f"[cyan]Analizando: {analyzer.url}[/cyan]")

            analyzer.analyze_url()
            analyzer.response = analyzer.make_request()

            if not analyzer.response:
                console.print("[red]❌ No se pudo obtener respuesta del servidor.[/red]")
                sys.exit(1)

            analyzer.analyze_headers(analyzer.response)
            analyzer.analyze_security(analyzer.response)
            analyzer.analyze_vulnerabilities()

            # Consultar CVEs reales de NVD
            techs = detect_technologies(analyzer.response, analyzer.html)
            if techs:
                result, analyzer.last_nvd_request = lookup_cves(
                    techs, analyzer.cache_path, analyzer.last_nvd_request
                )
                analyzer.cve_lookup = result

            analyzer.generate_report(interactive=False)

            console.print(f"[bold green]URL:[/bold green] {analyzer.url}")
            console.print(f"[bold green]Estado:[/bold green] {analyzer.status_code}")
            console.print(f"[bold green]Vulnerabilidades:[/bold green] {len(analyzer.vulnerabilities)}")
            console.print(f"[bold green]CVEs encontrados:[/bold green] "
                          f"{sum(len(e.get('cves', [])) for e in (analyzer.cve_lookup or {}).values())}")
            console.print(f"[bold green]Puntuación:[/bold green] {analyzer.security_score}/{analyzer.max_score}")
            sys.exit(0)
        else:
            # ---- Modo interactivo ----
            analyzer.run()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Programa interrumpido por el usuario[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e!s}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
