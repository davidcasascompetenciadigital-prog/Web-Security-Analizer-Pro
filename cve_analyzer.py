#!/usr/bin/env python3
"""
Módulo de análisis de CVEs offline usando feeds de FKIE-CAD
Versión con soporte completo para el formato FKIE-CAD

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
import re


class LocalCVEDatabase:
    """Gestor de base de datos local de CVEs desde FKIE-CAD"""

    BASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/"
    ALL_CVES_FILE = "CVE-All.json.xz"
    METADATA_URL = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest"

    def __init__(self, cache_dir: str = "./cve_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

        self.cves_file = self.cache_dir / self.ALL_CVES_FILE
        self.metadata_file = self.cache_dir / "metadata.json"
        self.cves_list = []
        self.cves_data = None
        self.last_update = None
        self.version = None
        self.is_loaded = False
        self.total_cves = 0

        self._load_metadata()

    def _load_metadata(self):
        """Carga metadatos guardados"""
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
        """Guarda metadatos"""
        data = {
            'version': self.version,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'file_size': self.cves_file.stat().st_size if self.cves_file.exists() else 0,
            'cves_count': self.total_cves
        }
        with open(self.metadata_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _get_latest_version_info(self) -> Tuple[str, str]:
        """Obtiene información de la última versión desde GitHub"""
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
        """Verifica si hay una nueva versión disponible"""
        latest_version, download_url = self._get_latest_version_info()
        if not latest_version or not download_url:
            return False, "No se pudo verificar"
        if not self.version:
            return True, f"Nueva versión {latest_version} disponible (sin versión local)"
        if self.version != latest_version:
            return True, f"Nueva versión {latest_version} disponible (actual: {self.version})"
        if not self.cves_file.exists():
            return True, "Archivo local no encontrado"
        return False, f"Versión actualizada ({self.version})"

    def download_cves(self, force: bool = False) -> bool:
        """Descarga el archivo de CVEs desde FKIE-CAD"""
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
            self._save_metadata()

            return self.load_cves()

        except Exception as e:
            print(f"\n❌ Error descargando CVEs: {e}")
            return False

    def load_cves(self) -> bool:
        """Carga la base de datos de CVEs en memoria"""
        if not self.cves_file.exists():
            print("❌ Archivo de CVEs no encontrado")
            return False

        try:
            print("📂 Cargando base de datos de CVEs...")
            
            with lzma.open(self.cves_file, 'rt', encoding='utf-8') as f:
                data = json.load(f)

            if 'cve_items' in data:
                self.cves_list = data.get('cve_items', [])
                print(f"   Usando clave 'cve_items'")
            elif 'vulnerabilities' in data:
                self.cves_list = data.get('vulnerabilities', [])
                print(f"   Usando clave 'vulnerabilities'")
            elif 'CVE_Items' in data:
                self.cves_list = data.get('CVE_Items', [])
                print(f"   Usando clave 'CVE_Items'")
            else:
                for key, value in data.items():
                    if isinstance(value, list) and len(value) > 0:
                        if 'cve' in value[0] or 'id' in value[0]:
                            self.cves_list = value
                            print(f"   Usando clave '{key}'")
                            break

            self.cves_data = data
            self.total_cves = len(self.cves_list)
            self.is_loaded = True
            self._save_metadata()

            print(f"✅ CVEs cargados: {self.total_cves}")
            return True

        except MemoryError:
            print("❌ Error: Memoria insuficiente para cargar todos los CVEs")
            return False
        except Exception as e:
            print(f"❌ Error cargando CVEs: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _parse_version(self, version_str: str) -> Tuple[int, ...]:
        """Convierte una versión a tupla para comparación"""
        if not version_str or version_str == '*':
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
        if start and start != 'N/A':
            start_ver = self._parse_version(start)
            if start_ver and ver < start_ver:
                return False
        
        # Verificar fin
        if end and end != 'N/A':
            end_ver = self._parse_version(end)
            if end_ver and ver >= end_ver:
                return False
        
        return True

    def search_cves_by_technology(self, technology: str, version: str = None) -> List[Dict]:
        """
        Busca CVEs que afectan a una tecnología específica
        
        Args:
            technology: Nombre de la tecnología (ej: nginx, wordpress, php)
            version: Versión específica (opcional)
            
        Returns:
            Lista de CVEs encontrados
        """
        if not self.is_loaded or not self.cves_list:
            print("📂 Base de datos no cargada. Cargando...")
            if not self.load_cves():
                print("❌ Error cargando base de datos")
                return []

        results = []
        tech_lower = technology.lower()

        for vuln in self.cves_list:
            cve_data = vuln
            configurations = cve_data.get('configurations', [])
            if not configurations:
                continue

            found = False
            for config in configurations:
                if found:
                    break
                for node in config.get('nodes', []):
                    if found:
                        break
                    for cpe_match in node.get('cpeMatch', []):
                        # FKIE-CAD usa 'criteria' en lugar de 'cpe23Uri'
                        cpe_string = cpe_match.get('criteria', '').lower()
                        
                        # Buscar la tecnología en el CPE
                        if tech_lower in cpe_string:
                            # Si no hay versión, considerar encontrado
                            if not version:
                                found = True
                                break
                            
                            # Verificar rangos de versión
                            version_start = cpe_match.get('versionStartIncluding', '')
                            version_end = cpe_match.get('versionEndExcluding', '')
                            
                            if self._version_in_range(version, version_start, version_end):
                                found = True
                                break
                            
                            # También verificar si la versión está en el CPE
                            parts = cpe_string.split(':')
                            if len(parts) > 4:
                                cpe_version = parts[4]
                                if version in cpe_version or cpe_version in version:
                                    found = True
                                    break
                    if found:
                        break
                if found:
                    break

            if found:
                severity = self._get_severity(cve_data)
                
                description = ""
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                cve_info = {
                    'id': cve_data.get('id', 'Unknown'),
                    'sourceIdentifier': cve_data.get('sourceIdentifier', ''),
                    'published': cve_data.get('published', ''),
                    'lastModified': cve_data.get('lastModified', ''),
                    'vulnStatus': cve_data.get('vulnStatus', ''),
                    'descriptions': cve_data.get('descriptions', []),
                    'metrics': cve_data.get('metrics', {}),
                    'configurations': cve_data.get('configurations', []),
                    'severity': severity
                }
                results.append(cve_info)

        return results

    def _get_severity(self, cve_data: Dict) -> Dict:
        """Extrae la severidad de las métricas del CVE"""
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
                if 'baseSeverity' in metric:
                    severity['severity'] = metric['baseSeverity']
                else:
                    score = cvss.get('baseScore', 0)
                    if score >= 9.0:
                        severity['severity'] = 'CRITICAL'
                    elif score >= 7.0:
                        severity['severity'] = 'HIGH'
                    elif score >= 4.0:
                        severity['severity'] = 'MEDIUM'
                    elif score >= 0.1:
                        severity['severity'] = 'LOW'
                    else:
                        severity['severity'] = 'UNKNOWN'
                severity['vector'] = cvss.get('vectorString', 'N/A')

        elif 'cvssMetricV30' in metrics:
            metric = metrics['cvssMetricV30'][0]
            if 'cvssData' in metric:
                cvss = metric['cvssData']
                severity['score'] = cvss.get('baseScore', 'N/A')
                if 'baseSeverity' in metric:
                    severity['severity'] = metric['baseSeverity']
                else:
                    score = cvss.get('baseScore', 0)
                    if score >= 9.0:
                        severity['severity'] = 'CRITICAL'
                    elif score >= 7.0:
                        severity['severity'] = 'HIGH'
                    elif score >= 4.0:
                        severity['severity'] = 'MEDIUM'
                    elif score >= 0.1:
                        severity['severity'] = 'LOW'
                    else:
                        severity['severity'] = 'UNKNOWN'
                severity['vector'] = cvss.get('vectorString', 'N/A')

        return severity

    def get_cves_for_site(self, technologies: List[Tuple[str, str]]) -> Dict[str, List[Dict]]:
        """Obtiene CVEs para múltiples tecnologías"""
        results = {}

        for tech, version in technologies:
            print(f"  🔍 Buscando CVEs para {tech} {version}...")
            cves = self.search_cves_by_technology(tech, version)
            results[f"{tech} {version}"] = {
                'count': len(cves),
                'cves': cves
            }

        return results

    def get_statistics(self) -> Dict:
        """Obtiene estadísticas de la base de datos"""
        if not self.is_loaded:
            return {
                'status': 'No cargada',
                'total_cves': self.total_cves,
                'version': self.version,
                'last_update': self.last_update.isoformat() if self.last_update else 'Unknown'
            }

        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}

        for vuln in self.cves_list:
            cve_data = vuln
            severity = self._get_severity(cve_data)
            sev = severity.get('severity', 'UNKNOWN')
            if sev in severity_count:
                severity_count[sev] += 1
            else:
                severity_count['UNKNOWN'] += 1

        return {
            'status': 'Cargada',
            'total_cves': self.total_cves,
            'severity_count': severity_count,
            'last_update': self.last_update.isoformat() if self.last_update else 'Unknown',
            'version': self.version
        }
