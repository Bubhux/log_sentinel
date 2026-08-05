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
