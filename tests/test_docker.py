import pytest
from unittest.mock import MagicMock, patch
from secuscan.core.docker_manager import DockerManager
import docker

@pytest.fixture
def mock_docker_client():
    with patch('docker.from_env') as mock_env:
        mock_client = MagicMock()
        mock_env.return_value = mock_client
        yield mock_client

def test_docker_available(mock_docker_client):
    manager = DockerManager()
    assert manager.is_available() is True

def test_docker_not_available():
    with patch('docker.from_env', side_effect=docker.errors.DockerException):
        manager = DockerManager()
        assert manager.is_available() is False

def test_pull_image_local(mock_docker_client, capsys):
    manager = DockerManager()
    # Mock image found
    mock_docker_client.images.get.return_value = MagicMock()
    
    manager.pull_image()
    
    mock_docker_client.images.get.assert_called_with(manager.MOBSF_IMAGE)
    mock_docker_client.images.pull.assert_not_called()

def test_pull_image_remote(mock_docker_client):
    manager = DockerManager()
    # Mock image not found, then pull
    mock_docker_client.images.get.side_effect = docker.errors.ImageNotFound("msg")
    
    manager.pull_image()
    
    mock_docker_client.images.pull.assert_called_with(manager.MOBSF_IMAGE)
