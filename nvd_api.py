#!/usr/bin/env python3
"""
Módulo de consulta a la API de NVD (National Vulnerability Database)
Con soporte para API Key configurable

Autor: David Casas M. - Competencia Digital
Licencia: CC BY-NC 4.0
"""

import requests
import time
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode
import re

class NVDAPI:
    """
    Cliente para la API de NVD (National Vulnerability Database)
    
    Sin API key: Rate limit 5 peticiones/30 segundos
    Con API key: Rate limit 50 peticiones/30 segundos
    
    Documentación: https://nvd.nist.gov/developers/vulnerabilities
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: str = None):
        """
        Inicializa el cliente de NVD API
        
        Args:
            api_key: API Key de NVD (opcional). Si no se proporciona,
                    se busca en la variable de entorno NVD_API_KEY
        """
        # Si no se proporciona API key, buscar en variables de entorno
        if not api_key:
            api_key = os.environ.get('NVD_API_KEY', None)
        
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({'apiKey': api_key})
            self.rate_limit = 0.6  # 0.6 segundos (50 peticiones/30s)
            self.has_api_key = True
            print("   ✅ API Key de NVD configurada (rate limit: 50 peticiones/30s)")
        else:
            self.rate_limit = 6.0  # 6 segundos (5 peticiones/30s)
            self.has_api_key = False
            print("   ℹ️  Sin API Key (rate limit: 5 peticiones/30s)")
            print("   💡 Registra una API key gratis en: https://nvd.nist.gov/developers/request-an-api-key")
        
        self.last_request = 0
    
    def set_api_key(self, api_key: str):
        """Permite configurar la API key después de la inicialización"""
        self.api_key = api_key
        if api_key:
            self.session.headers.update({'apiKey': api_key})
            self.rate_limit = 0.6
            self.has_api_key = True
            print("   ✅ API Key de NVD actualizada (rate limit: 50 peticiones/30s)")
        else:
            self.session.headers.pop('apiKey', None)
            self.rate_limit = 6.0
            self.has_api_key = False
            print("   ℹ️  API Key eliminada (rate limit: 5 peticiones/30s)")
    
    def _wait_for_rate_limit(self):
        """Espera el tiempo necesario para respetar el rate limit"""
        elapsed = time.time() - self.last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request = time.time()
    
    def _build_cpe_query(self, technology: str, version: str = None) -> str:
        """
        Construye una consulta CPE para la búsqueda en NVD
        Formato: cpe:2.3:vendor:product:version:*:*:*:*:*:*:*
        """
        tech_lower = technology.lower()
        
        # Mapeo de tecnologías a sus vendors comunes en CPE
        vendor_map = {
            'nginx': 'f5',
            'apache': 'apache',
            'wordpress': 'wordpress',
            'php': 'php',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'openssl': 'openssl',
            'python': 'python',
            'nodejs': 'nodejs',
            'django': 'djangoproject',
            'odoo': 'odoo',
            'rails': 'rubyonrails',
            'express': 'expressjs',
            'jquery': 'jquery',
            'bootstrap': 'twbs',
            'react': 'facebook',
            'angular': 'google',
            'vuejs': 'vuejs',
            'tomcat': 'apache',
            'iis': 'microsoft',
            'caddy': 'caddyserver',
            'gunicorn': 'gunicorn',
            'uwsgi': 'unbit'
        }
        
        vendor = vendor_map.get(tech_lower, tech_lower)
        product = tech_lower
        
        if version and version != 'unknown' and version != 'Unknown' and version != '':
            version_clean = version.split()[0].strip()
            version_clean = re.sub(r'[^0-9.]', '', version_clean)
            if version_clean and version_clean != '':
                return f"cpe:2.3:*:{vendor}:{product}:{version_clean}:*:*:*:*:*:*:*"
        
        return f"cpe:2.3:*:{vendor}:{product}:*:*:*:*:*:*:*"
    
    def search_cves(self, technology: str, version: str = None, 
                   max_results: int = 50, days_back: int = 730) -> List[Dict]:
        """
        Busca CVEs para una tecnología específica usando la API de NVD
        
        Args:
            technology: Nombre de la tecnología (ej. nginx, wordpress, php)
            version: Versión específica (opcional)
            max_results: Máximo de resultados a devolver
            days_back: Días hacia atrás para buscar (default: 730 días = 2 años)
            
        Returns:
            Lista de CVEs encontrados
        """
        tech_display = f"{technology} {version if version else ''}".strip()
        print(f"\n   🔍 Buscando {tech_display} en NVD API...")
        
        cpe_query = self._build_cpe_query(technology, version)
        print(f"      📌 CPE: {cpe_query}")
        
        params = {
            'cpeName': cpe_query,
            'resultsPerPage': min(max_results, 2000),
            'startIndex': 0
        }
        
        if days_back:
            start_date = (datetime.now() - timedelta(days=days_back)).isoformat()
            params['pubStartDate'] = start_date
            
        results = []
        
        try:
            self._wait_for_rate_limit()
            
            print(f"      ⏳ Consultando NVD...")
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                total_results = data.get('totalResults', 0)
                print(f"      📊 Total encontrados en NVD: {total_results}")
                
                if total_results == 0:
                    print(f"      ℹ️  No se encontraron CVEs para {tech_display}")
                    return []
                
                for vuln in vulnerabilities:
                    cve_data = vuln.get('cve', {})
                    cve_info = self._extract_cve_info(cve_data)
                    results.append(cve_info)
                    
                    if len(results) >= max_results:
                        break
                
                print(f"      ✅ Devueltos: {len(results)} CVEs")
                
            elif response.status_code == 404:
                print(f"      ⚠️  CPE no encontrado en NVD")
                if version:
                    print(f"      🔄 Reintentando sin versión...")
                    return self.search_cves(technology, None, max_results, days_back)
                return []
                
            elif response.status_code == 403:
                print(f"      ⚠️  Límite de API alcanzado. Esperando 60 segundos...")
                time.sleep(60)
                return self.search_cves(technology, version, max_results, days_back)
            else:
                print(f"      ❌ Error: {response.status_code}")
                if response.text:
                    print(f"      {response.text[:200]}")
                
        except requests.exceptions.Timeout:
            print("      ❌ Timeout en la petición a NVD")
        except Exception as e:
            print(f"      ❌ Error: {e}")
            
        return results
    
    def _extract_cve_info(self, cve_data: Dict) -> Dict:
        """Extrae información relevante de un CVE"""
        cve_id = cve_data.get('id', 'Unknown')
        
        description = ""
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        severity = {'score': 'N/A', 'severity': 'UNKNOWN', 'vector': 'N/A'}
        metrics = cve_data.get('metrics', {})
        
        if 'cvssMetricV31' in metrics:
            metric = metrics['cvssMetricV31'][0]
            if 'cvssData' in metric:
                cvss = metric['cvssData']
                severity['score'] = cvss.get('baseScore', 'N/A')
                severity['severity'] = metric.get('baseSeverity', 'UNKNOWN')
                severity['vector'] = cvss.get('vectorString', 'N/A')
        elif 'cvssMetricV30' in metrics:
            metric = metrics['cvssMetricV30'][0]
            if 'cvssData' in metric:
                cvss = metric['cvssData']
                severity['score'] = cvss.get('baseScore', 'N/A')
                severity['severity'] = metric.get('baseSeverity', 'UNKNOWN')
                severity['vector'] = cvss.get('vectorString', 'N/A')
        elif 'cvssMetricV2' in metrics:
            metric = metrics['cvssMetricV2'][0]
            severity['score'] = metric.get('baseScore', 'N/A')
            severity['severity'] = metric.get('severity', 'UNKNOWN')
        
        return {
            'id': cve_id,
            'descriptions': [{'lang': 'en', 'value': description}] if description else [],
            'severity': severity,
            'published': cve_data.get('published', ''),
            'lastModified': cve_data.get('lastModified', ''),
            'vulnStatus': cve_data.get('vulnStatus', '')
        }
    
    def search_cves_for_site(self, technologies: List[Tuple[str, str]]) -> Dict[str, List[Dict]]:
        """Busca CVEs para múltiples tecnologías"""
        results = {}
        total_tech = len(technologies)
        current = 0
        
        print("\n" + "=" * 70)
        print("🌐 CONSULTANDO NVD API")
        print("=" * 70)
        print(f"📋 Tecnologías a consultar: {total_tech}")
        print(f"📊 Rate limit: {'50' if self.has_api_key else '5'} peticiones cada 30 segundos")
        print("=" * 70 + "\n")
        
        for tech, version in technologies:
            current += 1
            print(f"\n   📌 [{current}/{total_tech}] {tech} {version}")
            print("   " + "-" * 50)
            
            cves = self.search_cves(tech, version, max_results=50, days_back=730)
            
            if not cves and version and version != 'unknown':
                print(f"      🔄 Reintentando sin versión específica...")
                cves = self.search_cves(tech, None, max_results=50, days_back=730)
            
            results[f"{tech} {version}"] = {
                'count': len(cves),
                'cves': cves
            }
            
            if len(cves) > 0:
                print(f"\n   ✅ {tech} {version}: {len(cves)} CVEs encontrados")
                for i, cve in enumerate(cves[:3], 1):
                    sev = cve.get('severity', {}).get('severity', 'UNKNOWN')
                    score = cve.get('severity', {}).get('score', 'N/A')
                    print(f"      {i}. {cve.get('id')} [{sev}] Score: {score}")
                if len(cves) > 3:
                    print(f"      ... y {len(cves) - 3} más")
            else:
                print(f"\n   ℹ️ {tech} {version}: 0 CVEs encontrados")
                print(f"      💡 Sugerencia: Prueba con la base de datos FKIE-CAD (opción 5)")
            
            if current < total_tech:
                wait_time = self.rate_limit
                print(f"\n   ⏳ Esperando {wait_time:.1f}s para respetar rate limit...")
                time.sleep(wait_time)
        
        print("\n" + "=" * 70)
        print("✅ BÚSQUEDA COMPLETADA")
        print("=" * 70)
        
        return results
