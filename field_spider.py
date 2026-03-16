#!/usr/bin/env python3
"""FieldSpider: Passive web form and upload surface mapper.

This tool crawls a target website and inventories text input and file upload
opportunities that could be *worth manual security review*. It intentionally
avoids sending attack payloads.

Use only on systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, asdict
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urldefrag, urlparse
from urllib.request import Request, urlopen


USER_AGENT = "FieldSpider/1.0 (+passive-surface-mapper)"

COLOR_TEXT_FIELD = "\033[96m"
COLOR_FILE_FIELD = "\033[95m"
COLOR_RESET = "\033[0m"

# Optional built-in banner slot.
# Paste your own ASCII art between these triple quotes for a default banner.
# Example:
# CUSTOM_BANNER = r"""
#  ______ _      _     _ ____        _     _
# |  ____(_)    | |   | / __ \      | |   | |
# | |__   _  ___| | __| | |  | |_ __ | | __| |
# |  __| | |/ _ \ |/ _` | |  | | '_ \| |/ _` |
# | |    | |  __/ | (_| | |__| | |_) | | (_| |
# |_|    |_|\___|_|\__,_|\____/| .__/|_|\__,_|
#                                | |
#                                |_|
# """
CUSTOM_BANNER = r"""

⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⢿⣆⠀⠀⠀⣠⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠈⠻⣷⣄⣠⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠀⠀⠈⠙⢻⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠀⠀⠀⠀⣸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠀⠀⠀⠀⣿⠻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡿⠿⠶⠶⢾⡟⠀⢿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣇⠀⠀⠀⣾⡇⠀⠈⠻⣷⣀⠀⣼⠗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠀⠀⢀⣿⣿⡀⠀⠀⠈⠛⢿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠀⠀⢸⣿⠹⣷⣄⠀⢀⣴⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⢷⣦⣼⣿⣤⣈⣙⣿⣿⣿⡟⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣏⠀⠀⢸⡇⠉⠉⠉⠉⢠⡿⠀⠘⢿⣆⡀⠀⠀⠀⣴⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠀⠀⣸⣧⠀⠀⠀⢀⣾⡇⠀⠀⠀⠙⠻⢶⣤⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣄⣠⣿⡟⠷⢶⣶⣾⣿⣧⠀⠀⠀⠀⠀⣠⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⡏⠉⣿⡃⠀⠀⣼⡟⠀⠙⢷⣦⣤⣤⣾⠟⠙⣷⡄⠀⠀⠀⠀⠀⠀⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠁⢠⣿⣇⣀⣴⣿⠀⠀⠀⠀⠈⣩⣿⡇⠀⠀⠈⠻⣶⣄⡀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠿⢿⡟⠙⠛⣿⣿⡀⠀⣀⣀⣴⠛⠹⣷⡀⠀⠀⠀⠀⠙⣻⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⠀⣿⠃⠀⣸⡟⠙⠻⣶⣿⡿⣷⣶⣤⡽⢿⣤⣀⣀⣤⡾⠋⢹⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣶⡿⠀⣰⡿⠁⣠⣶⠟⠹⣷⡀⠀⠀⠀⢀⣩⣿⡟⠉⠀⠀⠈⢻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⡇⢠⣿⣡⣾⠟⠁⠀⠀⠈⠻⣿⣿⡶⠟⠁⠸⣧⠀⠀⠀⠀⠀⠹⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣰⣿⠿⠋⢿⣦⡀⢀⣠⣴⠾⣿⡟⠀⠀⠀⠀⠹⣷⣤⡀⠀⠀⠀⠈⠻⣷⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣥⣤⣤⣴⣿⣿⣿⣭⣤⣤⣽⣷⣶⣤⣴⣶⣶⣤⣭⣿⣷⣶⣤⣤⣤⣤⣭⣿⣶⣶⣤⣤⣤⣤⣤⣤⣶⣶⣶⣦⣤⣀⠀
⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⡶⢶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⠶⠚⠛⠛⠉⠉⠉⠙⠛⠛⠶⢶⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⠶⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣤⡾⠟⠉⠀⠀⠀⠀⠉⠛⢷⣤⡀⠀⠀⣀⣴⠾⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠻⢶⣄⡀⠀⠀⣠⣶⠟⠋⠁⠀⠀⠀⠈⠙⠻⣦⣄⠀⠀⠀⠀⠀
⠀⠀⢀⣶⠟⢁⣠⣴⠶⠾⠿⠷⣦⣄⠀⠀⠈⠻⣶⡾⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣶⡿⠋⠀⠀⣀⣠⡶⠿⠿⠶⢶⣤⣈⠙⢷⣄⠀⠀⠀
⠀⠀⣿⣷⡾⠛⠁⠀⠀⠀⠀⠀⠀⠙⠻⣦⣀⣼⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣄⣠⡾⠋⠁⠀⠀⠀⠀⠀⠈⠙⠻⣦⣿⡇⠀⠀
⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣍⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⠀⠀⠀⠀⣾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡆⠀⠀⠀⢀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⣾⠟⠉⠉⠉⠉⠉⠙⠛⠷⢾⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⠶⠟⠛⠉⠉⠉⠉⠉⠙⠿⣦⠀⠀⠀⠀
⠀⠀⣴⠟⠁⢀⣠⣤⣤⣤⣀⣀⣀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⢀⣀⣀⣠⣤⣤⣤⡀⠀⠙⣿⡄⠀⠀
⢀⣼⠋⢀⣴⠟⠉⠀⠀⠀⠀⠉⠛⠛⢿⡇⠀⠀⠀⠀⠀⠀⠀⣀⣤⡴⠾⠟⠛⠛⠛⠛⠛⠛⠻⠶⢤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠟⠛⠉⠁⠀⠀⠀⠈⠛⢷⣄⠈⢿⡆⠀
⣼⠇⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⠀⠀⠀⠀⢀⣴⡾⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠷⣦⣄⠀⠀⠀⠀⠀⢠⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣷⡈⢿⡀
⣿⣾⠏⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣬⣿⡀⠀⠀⣰⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣷⡄⠀⠀⠀⣼⣧⣤⣤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠈⢷⣼⡇
⠀⠀⠀⠀⠀⠀⢀⣴⠿⠛⠉⠉⠁⠀⠀⠘⣷⡀⣼⠏⠀⠀⣠⡾⠿⣿⣿⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣄⠀⣰⠟⠀⠀⠀⠉⠉⠙⠻⢷⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣾⠃⠀⢀⣀⣤⣤⡤⠤⠤⢼⣿⠏⠀⠀⢸⡏⠀⣾⣿⡃⠀⢹⣆⠀⠀⠀⠀⢠⡶⠿⢿⣿⡻⣶⡄⠀⠀⢿⣶⡿⠤⠤⠤⣤⣤⣄⣀⠀⠈⢿⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣼⠇⠀⣴⠟⠉⠀⠀⠀⠀⠀⢰⡿⠀⠀⠀⢸⣆⠀⠻⣿⣿⣿⣿⡏⠀⠀⠀⠀⣿⣧⣐⣼⣿⡇⠈⣿⠀⠀⠘⣷⡀⠀⠀⠀⠀⠀⠈⠙⣷⡀⠈⢿⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⡟⢀⣾⠏⠀⠀⠀⠀⠀⠀⣠⣾⣇⠀⠀⠀⠈⠻⣦⣤⣀⣭⣶⠟⠀⠀⠀⠀⠀⣿⡻⢿⡿⠟⠁⢀⣿⠀⠀⠀⣿⢻⣦⡀⠀⠀⠀⠀⠀⠈⢿⡄⠸⣷⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣾⡇⣼⠇⠀⠀⠀⠀⠀⠀⣼⠟⠘⣿⡀⠀⠀⠀⠀⠀⠉⠉⠉⢀⡄⠙⠁⠀⠶⠆⠈⠻⣦⣤⣤⣴⠟⠁⠀⠀⠀⣿⠀⠙⣷⡄⠀⠀⠀⠀⠀⠈⣿⡄⣿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠻⣷⡟⠀⠀⠀⠀⠀⠀⣼⠏⠀⢀⣼⢷⣄⠀⠀⠀⠀⠀⠠⠴⣿⢷⣤⣀⣀⣀⣨⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡄⠀⠈⣿⡄⠀⠀⠀⠀⠀⠘⢷⡿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡏⠀⠀⣼⠏⠈⠙⢷⣤⣀⠀⠀⠀⠀⠙⠾⠋⠉⠉⢿⡽⠛⠛⠀⠀⠀⠀⠀⠀⠀⣰⡿⠉⢿⡀⠀⠘⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⣰⡏⠀⠀⠀⠀⠈⠙⠻⠶⢦⣤⣄⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣴⠿⠋⠀⠀⠘⣷⠀⠀⢹⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡄⠀⠸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠛⠛⠛⠛⠛⠛⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⢠⡿⠀⠀⣼⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣆⠀⢻⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠁⢀⣾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣧⡀⠻⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡿⢁⣰⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢦⣜⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⣏⣴⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""


def resolve_banner_text(banner_file: Optional[str], banner_text: Optional[str]) -> str:
    if banner_text:
        return banner_text.encode("utf-8").decode("unicode_escape").rstrip("\n")
    if banner_file:
        banner_text = fetch_text(banner_file, timeout=10) if banner_file.startswith(("http://", "https://")) else None
        if banner_text is None:
            try:
                with open(banner_file, "r", encoding="utf-8") as handle:
                    return handle.read().rstrip("\n")
            except OSError:
                return ""
        return banner_text.rstrip("\n")
    return CUSTOM_BANNER.strip("\n")


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def colorize(label: str, color_code: str) -> str:
    if not supports_color():
        return label
    return f"{color_code}{label}{COLOR_RESET}"


@dataclass
class FormFinding:
    page_url: str
    form_action: str
    form_method: str
    enctype: str
    text_fields: List[str]
    password_fields: List[str]
    textarea_fields: List[str]
    file_fields: List[str]
    has_csrf_token: bool
    risk_notes: List[str]


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: Set[str] = set()
        self.forms: List[Dict] = []
        self._active_form: Optional[Dict] = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}

        if tag == "a":
            href = attr.get("href", "").strip()
            if href:
                self.links.add(href)
            return

        if tag == "form":
            self._active_form = {
                "action": attr.get("action", ""),
                "method": attr.get("method", "get").upper(),
                "enctype": attr.get("enctype", "application/x-www-form-urlencoded"),
                "inputs": [],
                "textareas": [],
            }
            return

        if self._active_form is None:
            return

        if tag == "input":
            input_type = attr.get("type", "text").lower()
            name = attr.get("name") or attr.get("id") or "(unnamed)"
            self._active_form["inputs"].append({"type": input_type, "name": name})
        elif tag == "textarea":
            name = attr.get("name") or attr.get("id") or "(unnamed)"
            self._active_form["textareas"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._active_form is not None:
            self.forms.append(self._active_form)
            self._active_form = None


def normalize(url: str) -> str:
    clean, _frag = urldefrag(url)
    return clean.rstrip("/") or clean


def fetch_html(url: str, timeout: int) -> Optional[str]:
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=timeout) as response:
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                return None
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")
    except Exception:
        return None


def fetch_text(url: str, timeout: int) -> Optional[str]:
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT})
        with urlopen(req, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")
    except Exception:
        return None


def same_host(base: str, candidate: str) -> bool:
    return urlparse(base).netloc == urlparse(candidate).netloc


def discover_urls_from_sitemap(start_url: str, timeout: int) -> Set[str]:
    parsed = urlparse(start_url)
    sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
    sitemap = fetch_text(sitemap_url, timeout=timeout)
    if not sitemap:
        return set()

    try:
        root = ET.fromstring(sitemap)
    except ET.ParseError:
        return set()

    discovered: Set[str] = set()
    for element in root.iter():
        if element.tag.endswith("loc") and element.text:
            next_url = normalize(element.text.strip())
            if next_url.startswith("http") and same_host(start_url, next_url):
                discovered.add(next_url)

    return discovered


def assess_form(page_url: str, form: Dict) -> FormFinding:
    text_types = {"text", "search", "email", "url", "tel", "number", "hidden"}
    text_fields = [i["name"] for i in form["inputs"] if i["type"] in text_types]
    password_fields = [i["name"] for i in form["inputs"] if i["type"] == "password"]
    file_fields = [i["name"] for i in form["inputs"] if i["type"] == "file"]
    textarea_fields = list(form["textareas"])

    field_names = [i["name"].lower() for i in form["inputs"]]
    has_csrf = any("csrf" in name or "token" in name for name in field_names)

    risk_notes: List[str] = []
    if text_fields or textarea_fields:
        risk_notes.append("Contains writable text input surface; review for SQLi/server-side validation controls.")
    if file_fields:
        risk_notes.append("Contains file upload field; review server-side content validation and storage isolation.")
    if form["method"] == "GET" and (text_fields or textarea_fields):
        risk_notes.append("Uses GET for writable parameters; sensitive data and parameters may be exposed in URLs/logs.")
    if not has_csrf and form["method"] == "POST":
        risk_notes.append("No obvious CSRF token field detected (heuristic only).")
    if form["enctype"].lower() == "multipart/form-data" and not file_fields:
        risk_notes.append("Multipart form without explicit file input; verify parser handling and expected fields.")

    return FormFinding(
        page_url=page_url,
        form_action=form["action"] or page_url,
        form_method=form["method"],
        enctype=form["enctype"],
        text_fields=text_fields,
        password_fields=password_fields,
        textarea_fields=textarea_fields,
        file_fields=file_fields,
        has_csrf_token=has_csrf,
        risk_notes=risk_notes,
    )


def crawl(start_url: str, max_pages: int, timeout: int) -> List[FormFinding]:
    findings: List[FormFinding] = []
    queue = deque([normalize(start_url)])
    visited: Set[str] = set()

    for candidate in discover_urls_from_sitemap(start_url, timeout=timeout):
        queue.append(candidate)

    while queue and len(visited) < max_pages:
        current = queue.popleft()
        if current in visited:
            continue

        visited.add(current)
        html = fetch_html(current, timeout=timeout)
        if not html:
            continue

        parser = FormParser()
        parser.feed(html)

        for form in parser.forms:
            findings.append(assess_form(current, form))
            action_url = normalize(urljoin(current, form.get("action") or ""))
            if action_url.startswith("http") and same_host(start_url, action_url) and action_url not in visited:
                queue.append(action_url)

        for href in parser.links:
            next_url = normalize(urljoin(current, href))
            if next_url.startswith("http") and same_host(start_url, next_url) and next_url not in visited:
                queue.append(next_url)

    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passive scanner for form fields and file upload opportunities (authorized testing only)."
    )
    parser.add_argument("url", help="Starting URL (e.g., https://example.com)")
    parser.add_argument("--max-pages", type=int, default=25, help="Maximum pages to crawl on same host")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Output results in JSON")
    parser.add_argument(
        "--banner-file",
        help="Optional path/URL to a text file containing an ASCII art banner to print before results",
    )
    parser.add_argument(
        "--banner-text",
        help="Inline ASCII banner text (supports escaped newlines like \\n)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    start = normalize(args.url)
    if not start.startswith("http://") and not start.startswith("https://"):
        print("[!] URL must include scheme (http:// or https://)", file=sys.stderr)
        return 2

    findings = crawl(start, max_pages=args.max_pages, timeout=args.timeout)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        banner_text = resolve_banner_text(args.banner_file, args.banner_text)
        if banner_text:
            print(banner_text)
        print(f"FieldSpider results for: {start}")
        print(f"Forms discovered: {len(findings)}")
        for i, finding in enumerate(findings, start=1):
            print("\n" + "=" * 80)
            print(f"[{i}] Page: {finding.page_url}")
            print(f"    Action: {finding.form_action}")
            print(f"    Method: {finding.form_method}")
            print(f"    EncType: {finding.enctype}")
            text_label = colorize("Text fields", COLOR_TEXT_FIELD)
            file_label = colorize("File fields", COLOR_FILE_FIELD)
            print(f"    {text_label}: {', '.join(finding.text_fields) if finding.text_fields else '-'}")
            print(f"    Textareas: {', '.join(finding.textarea_fields) if finding.textarea_fields else '-'}")
            print(f"    Password fields: {', '.join(finding.password_fields) if finding.password_fields else '-'}")
            print(f"    {file_label}: {', '.join(finding.file_fields) if finding.file_fields else '-'}")
            print(f"    CSRF token heuristic: {'present' if finding.has_csrf_token else 'not detected'}")
            if finding.risk_notes:
                print("    Notes:")
                for note in finding.risk_notes:
                    print(f"      - {note}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
