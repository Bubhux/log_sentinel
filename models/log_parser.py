import re
import csv
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
import os

# Configuration du logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class LogParser:
    """Parseur automatique de logs robuste (Syslog, Apache, CSV, JSON, Windows Events)"""

    # Patterns pour la détection automatique
    PATTERNS = {
        'syslog': re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)$'),
        'apache': re.compile(r'^(\S+)\s+-\s+-\s+\[(.*?)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)$'),
        'windows_events': re.compile(r'^EventID=\d+,\s+', re.IGNORECASE),
        'json': re.compile(r'^\s*[\{\[]'),  # Commence par { ou [
        'custom': re.compile(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\w+)$')
    }

    # Valeurs considérées comme nulles / vides
    NULL_VALUES = {'-', '', 'null', 'None', 'N/A',
                   'na', 'none', 'undefined', 'nan', 'nil'}

    # Formats de timestamp supportés
    TIMESTAMP_FORMATS = [
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S',
        '%d/%m/%Y %H:%M:%S',
        '%m/%d/%Y %H:%M:%S',
        '%Y/%m/%d %H:%M:%S',
        '%d-%m-%Y %H:%M:%S',
        '%m-%d-%Y %H:%M:%S',
        '%d/%b/%Y:%H:%M:%S %z',
        '%d/%b/%Y:%H:%M:%S',
        '%b %d %H:%M:%S',
        '%a %b %d %H:%M:%S %Y',
    ]

    # Mapping des noms de colonnes vers les champs standard
    COLUMN_MAPPING = {
        'timestamp': 'timestamp', 'time': 'timestamp', 'date': 'timestamp',
        'datetime': 'timestamp', 'ts': 'timestamp', 'log_time': 'timestamp',
        'src_ip': 'src_ip', 'source_ip': 'src_ip', 'src': 'src_ip',
        'source': 'src_ip', 'client_ip': 'src_ip', 'client': 'src_ip',
        'remote_ip': 'src_ip', 'remote_addr': 'src_ip',
        'dst_ip': 'dst_ip', 'dest_ip': 'dst_ip', 'destination_ip': 'dst_ip',
        'dst': 'dst_ip', 'dest': 'dst_ip', 'target_ip': 'dst_ip',
        'user': 'user', 'username': 'user', 'user_name': 'user',
        'account': 'user', 'login': 'user', 'auth_user': 'user',
        'port': 'port', 'dst_port': 'port', 'dest_port': 'port',
        'src_port': 'src_port', 'source_port': 'src_port', 'sport': 'src_port',
        'dport': 'port',
        'status': 'status', 'result': 'status', 'action': 'status',
        'event_type': 'status', 'outcome': 'status',
        'message': 'message', 'msg': 'message', 'text': 'message',
        'description': 'message', 'details': 'message',
        'service': 'service', 'app': 'service', 'application': 'service',
        'program': 'service', 'process': 'service',
        'protocol': 'protocol', 'proto': 'protocol', 'transport': 'protocol',
        'host': 'host', 'hostname': 'host', 'server': 'host', 'machine': 'host',
        'method': 'method', 'verb': 'method', 'http_method': 'method',
        'url': 'url', 'path': 'url', 'uri': 'url', 'request': 'url',
        'size': 'size', 'bytes': 'size', 'bytes_out': 'size', 'bytes_in': 'size',
        'content_length': 'size',
    }

    @staticmethod
    def detect_format(line: str) -> str:
        """Détecte le format d'une ligne de log"""
        line = line.strip()
        if not line:
            return 'unknown'

        # JSON ?
        if LogParser.PATTERNS['json'].match(line):
            try:
                json.loads(line)
                return 'json'
            except:
                pass

        # Autres formats
        for fmt, pattern in LogParser.PATTERNS.items():
            if fmt != 'json' and pattern.match(line):
                return fmt
        return 'unknown'

    @staticmethod
    def detect_csv_separator(filepath: str) -> str:
        """Détecte automatiquement le séparateur d'un fichier CSV"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                first_lines = [f.readline() for _ in range(5) if f.readline()]

            if not first_lines:
                return ','

            separators = [',', ';', '|', '\t']
            counts = {sep: 0 for sep in separators}

            for line in first_lines:
                for sep in separators:
                    counts[sep] += line.count(sep)

            best_sep = max(counts, key=counts.get)
            return best_sep if counts[best_sep] > 0 else ','
        except:
            return ','

    @staticmethod
    def detect_headers(headers: List[str]) -> Dict[str, str]:
        """Détecte les colonnes et les mappe aux champs standard"""
        mapping = {}

        for header in headers:
            header_lower = header.lower().strip()
            mapped = LogParser.COLUMN_MAPPING.get(header_lower)
            if mapped:
                mapping[header] = mapped
            else:
                for key, value in LogParser.COLUMN_MAPPING.items():
                    if key in header_lower or header_lower in key:
                        mapping[header] = value
                        break
                else:
                    mapping[header] = header_lower

        return mapping

    @staticmethod
    def _clean_value(value: Any) -> Optional[str]:
        """Nettoie une valeur et retourne None si c'est une valeur nulle"""
        if value is None:
            return None
        value = str(value).strip(' "\'')
        if not value or value.lower() in LogParser.NULL_VALUES:
            return None
        return value

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Convertit une valeur en int de manière sécurisée"""
        cleaned = LogParser._clean_value(value)
        if cleaned is None:
            return None
        try:
            return int(cleaned)
        except ValueError:
            match = re.search(r'(\d+)', cleaned)
            if match:
                return int(match.group(1))
            return None

    @staticmethod
    def _parse_timestamp_robust(timestamp_str: Any) -> str:
        """Parse un timestamp dans plusieurs formats et retourne ISO"""
        if not timestamp_str:
            return datetime.now().isoformat()

        timestamp_str = str(timestamp_str).strip(' "\'')

        try:
            dt = datetime.fromisoformat(timestamp_str)
            return dt.isoformat()
        except ValueError:
            pass

        for fmt in LogParser.TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.isoformat()
            except ValueError:
                continue

        try:
            dt = datetime.fromtimestamp(float(timestamp_str))
            return dt.isoformat()
        except:
            pass

        logger.warning(f"Timestamp non reconnu: {timestamp_str}")
        return datetime.now().isoformat()

    @staticmethod
    def parse_line(line: str, format_type: str = None) -> Optional[Dict]:
        """Parse une ligne de log et retourne un dictionnaire structuré"""
        line = line.strip()
        if not line:
            return None

        if format_type is None:
            format_type = LogParser.detect_format(line)

        # --- Syslog ---
        if format_type == 'syslog':
            match = LogParser.PATTERNS['syslog'].match(line)
            if match:
                timestamp, host, service, pid, message = match.groups()
                ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                user_pattern = r'user\s+(\w+)'
                port_pattern = r'port\s+(\d+)'

                return {
                    'timestamp': LogParser._parse_timestamp_robust(timestamp),
                    'host': host,
                    'service': service,
                    'pid': LogParser._safe_int(pid),
                    'message': message,
                    'src_ip': LogParser._clean_value(re.search(ip_pattern, message).group(1) if re.search(ip_pattern, message) else None),
                    'dst_ip': None,
                    'user': LogParser._clean_value(re.search(user_pattern, message).group(1) if re.search(user_pattern, message) else None),
                    'port': LogParser._safe_int(re.search(port_pattern, message).group(1)) if re.search(port_pattern, message) else None,
                    'status': 'success' if 'accepted' in message.lower() else 'failed' if 'failed' in message.lower() else 'unknown'
                }

        # --- Apache ---
        elif format_type == 'apache':
            match = LogParser.PATTERNS['apache'].match(line)
            if match:
                src_ip, timestamp, method, url, protocol, status, size = match.groups()
                return {
                    'timestamp': LogParser._parse_timestamp_robust(timestamp),
                    'src_ip': LogParser._clean_value(src_ip),
                    'dst_ip': None,
                    'method': method,
                    'url': url,
                    'protocol': protocol,
                    'status': LogParser._safe_int(status),
                    'size': LogParser._safe_int(size),
                    'user': None,
                    'port': None,
                    'message': f"{method} {url} {protocol}"
                }

        # --- Windows Events (NOUVEAU) ---
        elif format_type == 'windows_events':
            # Format: EventID=4625, User=admin, SourceIP=45.33.22.11, ...
            try:
                # Extraire les paires clé=valeur
                parts = line.split(',')
                data = {}
                for part in parts:
                    part = part.strip()
                    if '=' in part:
                        key, value = part.split('=', 1)
                        data[key.strip()] = value.strip()

                # Construire l'entrée
                return {
                    'timestamp': LogParser._parse_timestamp_robust(data.get('Timestamp', '')),
                    'src_ip': LogParser._clean_value(data.get('SourceIP')),
                    'dst_ip': LogParser._clean_value(data.get('DestIP')),
                    'user': LogParser._clean_value(data.get('User')),
                    'port': LogParser._safe_int(data.get('Port')),
                    'status': LogParser._clean_value(data.get('Status', 'unknown')) or 'unknown',
                    'message': data.get('Message', ''),
                    'service': LogParser._clean_value(data.get('ServiceName')),
                    'event_id': LogParser._safe_int(data.get('EventID')),
                    'host': LogParser._clean_value(data.get('Host')),
                }
            except Exception as e:
                logger.warning(f"Erreur parsing Windows Events: {e}")
                return None

        # --- Custom / CSV (pour les lignes simples) ---
        elif format_type == 'custom' or format_type == 'csv':
            parts = line.split(',')
            if len(parts) >= 6:
                try:
                    return {
                        'timestamp': LogParser._parse_timestamp_robust(parts[0]),
                        'src_ip': LogParser._clean_value(parts[1]) if len(parts) > 1 else None,
                        'dst_ip': LogParser._clean_value(parts[2]) if len(parts) > 2 else None,
                        'user': LogParser._clean_value(parts[3]) if len(parts) > 3 else None,
                        'port': LogParser._safe_int(parts[4]) if len(parts) > 4 else None,
                        'status': LogParser._clean_value(parts[5]) if len(parts) > 5 else 'unknown',
                        'message': parts[6] if len(parts) > 6 else ''
                    }
                except Exception as e:
                    logger.warning(
                        f"Erreur parsing ligne CSV: {e} - {line[:100]}")

        # --- JSON ---
        elif format_type == 'json':
            try:
                data = json.loads(line)
                return LogParser._parse_json_object(data)
            except:
                return None

        return None
