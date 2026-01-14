import pytest
from unittest.mock import MagicMock, patch
from secuscan.core.engine import ScanEngine
from secuscan.core.detection import ProjectType
from secuscan.scanners.models import Vulnerability

@pytest.fixture
def mock_scanner_factory():
    with patch('secuscan.core.engine.ScannerFactory') as mock:
        yield mock

@pytest.fixture
def mock_scanner_factory():
    with patch('secuscan.core.engine.ScannerFactory') as mock:
        yield mock

@pytest.fixture
def mock_detect():
    with patch('secuscan.core.engine.detect_project_type') as mock:
        yield mock

@pytest.fixture
def mock_docker_cls():
    with patch('secuscan.core.engine.DockerManager') as mock:
        yield mock

def test_engine_web_flow(mock_detect, mock_scanner_factory, mock_docker_cls):
    # Setup
    mock_detect.return_value = (ProjectType.WEB, {})
    
    # Mock Scanner
    mock_scanner_instance = MagicMock()
    mock_scanner_instance.scan.return_value = [
        Vulnerability(type="Test", file="test.py", severity="HIGH", description="Test Vuln")
    ]
    mock_scanner_factory.get_scanner.return_value = mock_scanner_instance
    
    # Run
    engine = ScanEngine("dummy/path")
    with patch('secuscan.core.engine.console') as mock_console: # Mute console
        engine.start()
    
    # Verify
    mock_detect.assert_called_once()
    mock_scanner_factory.get_scanner.assert_called_with(ProjectType.WEB, "dummy/path")
    mock_scanner_instance.scan.assert_called_once()

def test_engine_android_flow_with_docker(mock_detect, mock_scanner_factory, mock_docker_cls):
    # Setup
    mock_detect.return_value = (ProjectType.ANDROID, {})
    
    mock_scanner_instance = MagicMock()
    mock_scanner_instance.scan.return_value = []
    mock_scanner_factory.get_scanner.return_value = mock_scanner_instance
    
    # Setup Mock Docker Instance
    mock_docker_instance = mock_docker_cls.return_value
    mock_docker_instance.is_available.return_value = True
    
    engine = ScanEngine("dummy.apk")
    
    with patch('secuscan.core.engine.console') as mock_console:
        engine.start()
        
    mock_docker_instance.ensure_mobsf.assert_called_once()
    mock_scanner_factory.get_scanner.assert_called_with(ProjectType.ANDROID, "dummy.apk")
