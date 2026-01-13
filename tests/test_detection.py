import os
import shutil
import tempfile
import pytest
from secuscan.core.detection import detect_project_type, ProjectType

@pytest.fixture
def temp_dir():
    dir_path = tempfile.mkdtemp()
    yield dir_path
    shutil.rmtree(dir_path)

def test_detect_android_manifest(temp_dir):
    with open(os.path.join(temp_dir, 'AndroidManifest.xml'), 'w') as f:
        f.write('<manifest></manifest>')
    
    project_type, _ = detect_project_type(temp_dir)
    assert project_type == ProjectType.ANDROID

def test_detect_web_package_json(temp_dir):
    with open(os.path.join(temp_dir, 'package.json'), 'w') as f:
        f.write('{}')
    
    project_type, _ = detect_project_type(temp_dir)
    assert project_type == ProjectType.WEB

def test_detect_python_file_weighting(temp_dir):
    with open(os.path.join(temp_dir, 'app.py'), 'w') as f:
        f.write('print("hello")')
    
    project_type, _ = detect_project_type(temp_dir)
    assert project_type == ProjectType.WEB

def test_detect_unknown(temp_dir):
    with open(os.path.join(temp_dir, 'readme.txt'), 'w') as f:
        f.write('just text')
        
    project_type, _ = detect_project_type(temp_dir)
    assert project_type == ProjectType.UNKNOWN

def test_detect_single_file_apk(temp_dir):
    apk_path = os.path.join(temp_dir, 'test.apk')
    with open(apk_path, 'wb') as f:
        f.write(b'fake apk content')
        
    project_type, _ = detect_project_type(apk_path)
    assert project_type == ProjectType.ANDROID
