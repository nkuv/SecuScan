"""Tests for SonarQube manager."""

import pytest
from unittest.mock import MagicMock, patch
from secuscan.core.sonarqube_manager import SonarQubeManager
import docker


@pytest.fixture
def mock_docker_client():
    """Fixture to mock Docker client."""
    with patch('docker.from_env') as mock_env:
        mock_client = MagicMock()
        mock_env.return_value = mock_client
        yield mock_client


def test_sonarqube_available(mock_docker_client):
    """Test SonarQube manager when Docker is available."""
    manager = SonarQubeManager()
    assert manager.is_available() is True


def test_sonarqube_not_available():
    """Test SonarQube manager when Docker is not available."""
    with patch('docker.from_env', side_effect=docker.errors.DockerException):
        manager = SonarQubeManager()
        assert manager.is_available() is False


def test_pull_image(mock_docker_client):
    """Test image pulling when image is not found locally."""
    manager = SonarQubeManager()
    mock_docker_client.images.get.side_effect = docker.errors.ImageNotFound("msg")
    
    manager.pull_image("test:image")
    
    mock_docker_client.images.pull.assert_called_with("test:image")


def test_is_container_running_true(mock_docker_client):
    """Test container running check when container is running."""
    manager = SonarQubeManager()
    mock_docker_client.containers.get.return_value.status = "running"
    
    assert manager.is_container_running() is True


def test_is_container_running_false(mock_docker_client):
    """Test container running check when container is not found."""
    manager = SonarQubeManager()
    mock_docker_client.containers.get.side_effect = docker.errors.NotFound("msg")
    
    assert manager.is_container_running() is False


def test_start_sonarqube_already_running(mock_docker_client):
    """Test starting SonarQube when it's already running."""
    manager = SonarQubeManager()
    mock_docker_client.containers.get.return_value.status = "running"
    
    manager.start_sonarqube()
    
    mock_docker_client.containers.run.assert_not_called()


def test_start_sonarqube_not_running(mock_docker_client):
    """Test starting SonarQube when it's not running."""
    manager = SonarQubeManager()
    mock_docker_client.containers.get.side_effect = docker.errors.NotFound("msg")
    
    with patch.object(manager, 'wait_for_sonarqube'):
        manager.start_sonarqube()
        
    mock_docker_client.containers.run.assert_called_once()
    assert mock_docker_client.containers.run.call_args[1]['name'] == 'secuscan-sonarqube'


def test_run_scan(mock_docker_client):
    """Test running a SonarQube scan."""
    manager = SonarQubeManager()
    
    manager.run_scan("/tmp/scan_target")
    
    mock_docker_client.containers.run.assert_called()
    call_args = mock_docker_client.containers.run.call_args
    assert call_args[0][0] == manager.SCANNER_IMAGE
    assert "SONAR_HOST_URL" in call_args[1]['environment']
