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
