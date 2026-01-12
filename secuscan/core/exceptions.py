class SecuScanError(Exception):
    """Base exception for all SecuScan errors."""
    pass

class ConfigError(SecuScanError):
    """Raised when there is a configuration error."""
    pass

class DockerError(SecuScanError):
    """Raised when there is a Docker-related error."""
    pass

class ScanError(SecuScanError):
    """Raised during scanning failures."""
    pass
