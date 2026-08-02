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
