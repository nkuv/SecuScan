import os
import collections
from enum import Enum, auto
from typing import Dict, Tuple

class ProjectType(Enum):
    ANDROID = auto()
    WEB = auto()
    UNKNOWN = auto()

def detect_project_type(path: str) -> Tuple[ProjectType, Dict[str, int]]:
    """
    Analyzes the directory at `path` to determine the project type.
    Returns a tuple of (ProjectType, extension_counts).
    """
    
    if not os.path.exists(path):
        return ProjectType.UNKNOWN, {}

    extension_counts = collections.defaultdict(int)
    
    # 1. Handle Single File Input
    if os.path.isfile(path):
        _, ext = os.path.splitext(path)
        ext = ext.lower()
        extension_counts[ext] = 1
        
        if ext == '.apk':
            return ProjectType.ANDROID, dict(extension_counts)
        elif ext in {'.html', '.js', '.css', '.php', '.ts', '.jsx', '.tsx', '.vue', '.py', '.rb', '.go'}:
            return ProjectType.WEB, dict(extension_counts)
        return ProjectType.UNKNOWN, dict(extension_counts)

    # 2. Handle Directory Input
    has_android_manifest = False
    has_web_indicators = False
    
    # Heuristics
    web_indicators = {'package.json', 'index.html', 'yarn.lock'}
    exclude_dirs = {'.git', 'node_modules', 'venv', 'env', '__pycache__', 'build', 'dist', '.gradle', '.idea'}
    
    web_extensions = {'.html', '.js', '.css', '.php', '.ts', '.jsx', '.tsx', '.vue', '.py', '.rb', '.go'}
    android_extensions = {'.java', '.kt', '.xml', '.gradle'}
    
    for root, dirs, files in os.walk(path):
        # Filter out noisy directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        if 'AndroidManifest.xml' in files:
            has_android_manifest = True
        
        if any(f in web_indicators for f in files):
            has_web_indicators = True
            
        for file in files:
            _, ext = os.path.splitext(file)
            if ext:
                extension_counts[ext.lower()] += 1

    # Logic decision
    # Weighting System
    # Manifests are strong indicators (Weight: 10)
    # Extensions are weak indicators (Weight: 1)
    
    android_score = 0
    web_score = 0
    
    if has_android_manifest:
        android_score += 10
        
    if has_web_indicators:
        web_score += 10
        
    # Add extension counts
    web_score += sum(extension_counts[ext] for ext in web_extensions if ext in extension_counts)
    android_score += sum(extension_counts[ext] for ext in android_extensions if ext in extension_counts)
    
    if web_score > android_score:
        return ProjectType.WEB, dict(extension_counts)
    elif android_score >= web_score and android_score > 0:
        return ProjectType.ANDROID, dict(extension_counts)

    return ProjectType.UNKNOWN, dict(extension_counts)
