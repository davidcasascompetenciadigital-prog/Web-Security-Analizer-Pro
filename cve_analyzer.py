#!/usr/bin/env python3
"""
Módulo de análisis de CVEs offline usando feeds de FKIE-CAD
Versión con streaming usando ijson - Bajo consumo de memoria

Autor: David Casas M. - Competencia Digital
Licencia: CC BY-NC 4.0
"""

import os
import json
import lzma
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import gc

try:
    import ijson
    IJSON_AVAILABLE = True
except ImportError:
    IJSON_AVAILABLE = False
    print("⚠️  ijson no está instalado. Instalando...")
    import subprocess
    subprocess.check_call(['pip', 'install', 'ijson'])
    import ijson
    IJSON_AVAILABLE = True


class LocalCVEDatabase:
    """Gestor de base de datos local de CVEs - Streaming con ijson"""

    BASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/"
    ALL_CVES_FILE = "CVE-All.json.xz"
    METADATA_URL = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest"

    def __init__(self, cache_dir: str = "./cve_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

        self.cves_file = self.cache_dir / self.ALL_CVES_FILE
        self.metadata_file = self.cache_dir / "metadata.json"
        self.last_update = None
        self.version = None
        self.total_cves = 0
        self.is_loaded = False
        self.cves_list = []  # Lista de CVEs relevantes (solo para estadísticas)

        self._load_metadata()

    def _load_metadata(self):
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    self.version = data.get('version')
                    if data.get('last_update'):
                        self.last_update = datetime.fromisoformat(data.get('last_update'))
                    self.total_cves = data.get('cves_count', 0)
            except:
                pass

    def _save_metadata(self):
        data = {
            'version': self.version,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'file_size': self.cves_file.stat().st_size if self.cves_file.exists() else 0,
            'cves_count': self.total_cves
        }
        with open(self.metadata_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _get_latest_version_info(self) -> Tuple[str, str]:
        try:
            response = requests.get(self.METADATA_URL, timeout=10)
            response.raise_for_status()
            data = response.json()
            version = data.get('tag_name', 'unknown')
            download_url = None
            for asset in data.get('assets', []):
                if asset.get('name') == self.ALL_CVES_FILE:
                    download_url = asset.get('browser_download_url')
                    break
            return version, download_url
        except Exception as e:
            print(f"⚠️  Error obteniendo versión: {e}")
            return None, None

    def check_update_needed(self) -> Tuple[bool, str]:
        latest_version, download_url = self._get_latest_version_info()
        if not latest_version or not download_url:
            return False, "No se pudo verificar"
        if not self.version:
            return True, f"Nueva versión {latest_version} disponible"
        if self.version != latest_version:
            return True, f"Nueva versión {latest_version} disponible"
        if not self.cves_file.exists():
            return True, "Archivo local no encontrado"
        return False, f"Versión actualizada ({self.version})"

    def download_cves(self, force: bool = False) -> bool:
        if not force and self.cves_file.exists():
            needs_update, _ = self.check_update_needed()
            if not needs_update:
                print(f"✅ Archivo CVEs ya existe y está actualizado")
                return True

        print(f"📥 Descargando base de datos de CVEs...")
        print(f"   (esto puede tomar varios minutos)")

        try:
            latest_version, download_url = self._get_latest_version_info()
            if not download_url:
                download_url = f"{self.BASE_URL}{self.ALL_CVES_FILE}"

            response = requests.get(download_url, stream=True, timeout=120)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(self.cves_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\r   Progreso: {percent:.1f}%", end='')

            print(f"\n✅ Descarga completada")

            self.version = latest_version
            self.last_update = datetime.now()
            self.total_cves = 381325
            self._save_metadata()

            print(f"✅ Base de datos descargada. Total CVEs: ~{self.total_cves}")
            return True

        except Exception as e:
            print(f"\n❌ Error descargando CVEs: {e}")
            return False

    def load_cves(self) -> bool:
        if not self.cves_file.exists():
            print("❌ Archivo de CVEs no encontrado")
            return False

        self.is_loaded = True
        size_mb = self.cves_file.stat().st_size / (1024 * 1024)
        print(f"✅ Base de datos disponible: {self.cves_file}")
        print(f"   Tamaño: {size_mb:.1f} MB")
        print(f"   CVEs en base de datos: ~{self.total_cves}")
        return True

    def search_cves_by_technology(self, technology: str, version: str = None, max_results: int = 50) -> List[Dict]:
        """
        Busca CVEs usando ijson streaming - Muy bajo consumo de memoria
        """
        if not self.cves_file.exists():
            print("⚠️  Base de datos no descargada")
            return []

        results = []
        tech_lower = technology.lower()
        version_lower = version.lower() if version else None

        print(f"   🔍 Buscando {technology} {version} (streaming con ijson)...")

        try:
            # Abrir el archivo comprimido
            with lzma.open(self.cves_file, 'rb') as f:
                # Usar ijson para parsear el array de CVEs
                # La clave en FKIE-CAD es 'cve_items'
                parser = ijson.parse(f)
                
                processed = 0
                found = 0
                current_cve = None
                in_cve = False
                
                for prefix, event, value in parser:
                    # Detectar cuando empezamos un nuevo CVE
                    if prefix == 'cve_items.item' and event == 'start_map':
                        in_cve = True
                        current_cve = {}
                        processed += 1
                    
                    # Si estamos dentro de un CVE, recolectar datos
                    if in_cve and current_cve is not None:
                        # Extraer ID
                        if prefix.endswith('.id') and event == 'string':
                            current_cve['id'] = value
                        
                        # Extraer configuraciones (CPEs)
                        elif prefix.endswith('.criteria') and event == 'string':
                            if 'cpes' not in current_cve:
                                current_cve['cpes'] = []
                            current_cve['cpes'].append(value)
                        
                        # Extraer descripciones
                        elif 'descriptions' in prefix and event == 'string' and prefix.endswith('.value'):
                            if 'descriptions' not in current_cve:
                                current_cve['descriptions'] = []
                            # Obtener el idioma
                            lang_prefix = prefix.rsplit('.value', 1)[0] + '.lang'
                            # El idioma se procesa antes, así que lo guardamos
                            current_cve['descriptions'].append({'lang': 'en', 'value': value})
                        
                        # Extraer severidad
                        elif 'baseSeverity' in prefix and event == 'string':
                            if 'metrics' not in current_cve:
                                current_cve['metrics'] = {}
                            if 'cvssMetricV31' not in current_cve['metrics']:
                                current_cve['metrics']['cvssMetricV31'] = []
                            current_cve['metrics']['cvssMetricV31'].append({'baseSeverity': value})
                        
                        # Extraer score
                        elif 'baseScore' in prefix and event == 'number':
                            if 'metrics' in current_cve and 'cvssMetricV31' in current_cve['metrics']:
                                if current_cve['metrics']['cvssMetricV31']:
                                    current_cve['metrics']['cvssMetricV31'][-1]['baseScore'] = value
                    
                    # Detectar cuando terminamos un CVE
                    if prefix == 'cve_items.item' and event == 'end_map':
                        if current_cve and self._cve_matches(current_cve, tech_lower, version_lower):
                            cve_info = self._extract_cve_info(current_cve)
                            results.append(cve_info)
                            found += 1
                            if found >= max_results:
                                break
                        
                        in_cve = False
                        current_cve = None
                        
                        # Mostrar progreso cada 100 CVEs
                        if processed % 100 == 0:
                            print(f"\r   Procesados: {processed} CVEs | Encontrados: {found}", end='')

            print(f"\r   ✅ Procesados: {processed} CVEs | Encontrados: {found}   ")

        except MemoryError:
            print("   ❌ Error: Memoria insuficiente")
            return []
        except Exception as e:
            print(f"   ❌ Error buscando CVEs: {e}")
            return []

        return results

    def _cve_matches(self, cve_data: Dict, tech_lower: str, version_lower: str = None) -> bool:
        """Verifica si un CVE coincide con la tecnología buscada"""
        if not cve_data:
            return False
        
        # Buscar en CPEs (criteria)
        cpes = cve_data.get('cpes', [])
        for cpe in cpes:
            cpe_lower = cpe.lower()
            if tech_lower in cpe_lower:
                if version_lower:
                    parts = cpe_lower.split(':')
                    if len(parts) > 4:
                        cpe_version = parts[4]
                        if version_lower in cpe_version or cpe_version in version_lower:
                            return True
                else:
                    return True
        
        # Buscar en descripciones
        for desc in cve_data.get('descriptions', []):
            desc_text = desc.get('value', '').lower()
            if tech_lower in desc_text:
                if version_lower and version_lower in desc_text:
                    return True
                elif not version_lower:
                    return True
        
        return False

    def _extract_cve_info(self, cve_data: Dict) -> Dict:
        """Extrae información de un CVE"""
        severity = self._get_severity(cve_data)
        
        description = ""
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        return {
            'id': cve_data.get('id', 'Unknown'),
            'descriptions': [{'lang': 'en', 'value': description}] if description else [],
            'severity': severity,
            'published': cve_data.get('published', ''),
            'lastModified': cve_data.get('lastModified', ''),
            'vulnStatus': cve_data.get('vulnStatus', '')
        }

    def _get_severity(self, cve_data: Dict) -> Dict:
        """Extrae severidad de los datos del CVE"""
        severity = {
            'score': 'N/A',
            'severity': 'UNKNOWN',
            'vector': 'N/A'
        }
        
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            metric = metrics['cvssMetricV31'][0]
            severity['severity'] = metric.get('baseSeverity', 'UNKNOWN')
            severity['score'] = metric.get('baseScore', 'N/A')
        elif 'cvssMetricV30' in metrics:
            metric = metrics['cvssMetricV30'][0]
            severity['severity'] = metric.get('baseSeverity', 'UNKNOWN')
            severity['score'] = metric.get('baseScore', 'N/A')
        
        return severity

    def get_cves_for_site(self, technologies: List[Tuple[str, str]]) -> Dict[str, List[Dict]]:
        results = {}

        for tech, version in technologies:
            print(f"  🔍 Buscando CVEs para {tech} {version}...")
            cves = self.search_cves_by_technology(tech, version, max_results=50)
            results[f"{tech} {version}"] = {
                'count': len(cves),
                'cves': cves
            }

        return results

    def get_statistics(self) -> Dict:
        return {
            'status': 'Disponible',
            'total_cves': self.total_cves,
            'version': self.version,
            'last_update': self.last_update.isoformat() if self.last_update else 'Unknown'
        }
