#!/usr/bin/env python3
"""
Módulo de análisis de CVEs offline usando feeds de FKIE-CAD
Versión con soporte de rangos de versión (versionStartIncluding / versionEndExcluding)

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
import re

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
    """Gestor de base de datos local de CVEs - Con soporte de rangos de versión"""

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

    def _parse_version(self, version_str: str) -> Tuple[int, ...]:
        """Convierte una versión a tupla para comparación"""
        if not version_str or version_str == 'N/A' or version_str == '*':
            return ()
        try:
            # Limpiar la versión
            version_str = version_str.strip()
            # Si tiene prefijo 'v', quitarlo
            if version_str.startswith('v'):
                version_str = version_str[1:]
            # Separar por puntos y convertir a números
            parts = []
            for part in version_str.split('.'):
                try:
                    parts.append(int(part))
                except ValueError:
                    # Si no es número, intentar extraer números
                    nums = re.findall(r'\d+', part)
                    if nums:
                        parts.append(int(nums[0]))
                    else:
                        parts.append(0)
            return tuple(parts)
        except:
            return ()

    def _version_in_range(self, version: str, start: str, end: str) -> bool:
        """Verifica si una versión está dentro de un rango"""
        if not version:
            return True
        
        ver = self._parse_version(version)
        if not ver:
            return True
        
        # Verificar inicio
        if start and start != 'N/A' and start != '*':
            start_ver = self._parse_version(start)
            if start_ver and ver < start_ver:
                return False
        
        # Verificar fin
        if end and end != 'N/A' and end != '*':
            end_ver = self._parse_version(end)
            if end_ver and ver >= end_ver:
                return False
        
        return True

    def search_cves_by_technology(self, technology: str, version: str = None, max_results: int = 50) -> List[Dict]:
        """
        Busca CVEs usando ijson - Con soporte de rangos de versión
        """
        if not self.cves_file.exists():
            print("⚠️  Base de datos no descargada")
            return []

        results = []
        tech_lower = technology.lower()
        version_str = version if version else None

        print(f"   🔍 Buscando {technology} {version if version else '(todas)'}...")

        try:
            with lzma.open(self.cves_file, 'rb') as f:
                cves_iterator = ijson.items(f, 'cve_items.item')
                
                processed = 0
                found = 0
                
                for cve_data in cves_iterator:
                    processed += 1
                    
                    # Buscar en configurations
                    configs = cve_data.get('configurations', [])
                    found_match = False
                    
                    for config in configs:
                        if found_match:
                            break
                        for node in config.get('nodes', []):
                            if found_match:
                                break
                            for cpe_match in node.get('cpeMatch', []):
                                # FKIE-CAD usa 'criteria' en lugar de 'cpe23Uri'
                                criteria = cpe_match.get('criteria', '').lower()
                                
                                if tech_lower in criteria:
                                    # Si no hay versión específica, encontrado
                                    if not version_str:
                                        found_match = True
                                        break
                                    
                                    # Verificar rangos de versión
                                    version_start = cpe_match.get('versionStartIncluding', '')
                                    version_end = cpe_match.get('versionEndExcluding', '')
                                    
                                    if self._version_in_range(version_str, version_start, version_end):
                                        found_match = True
                                        break
                                    
                                    # También verificar si la versión está en el CPE
                                    parts = criteria.split(':')
                                    if len(parts) > 4:
                                        cpe_version = parts[4]
                                        if version_str in cpe_version or cpe_version in version_str:
                                            found_match = True
                                            break
                            if found_match:
                                break
                        if found_match:
                            break
                    
                    if found_match:
                        cve_info = self._extract_cve_info(cve_data)
                        results.append(cve_info)
                        found += 1
                        if found >= max_results:
                            break
                    
                    if processed % 1000 == 0:
                        print(f"\r   Procesados: {processed} CVEs | Encontrados: {found}", end='')
                    
                    # Limitar a 50,000 CVEs
                    if processed >= 50000:
                        print(f"\r   ⚠️  Límite de 50,000 CVEs alcanzado", end='')
                        break

            print(f"\r   ✅ Procesados: {processed} CVEs | Encontrados: {found}   ")

        except MemoryError:
            print("   ❌ Error: Memoria insuficiente")
            return []
        except Exception as e:
            print(f"   ❌ Error buscando CVEs: {e}")
            return []

        return results

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
