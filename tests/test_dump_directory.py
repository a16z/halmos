import tempfile
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

from halmos.solve import DumpDirectory, dirname
from halmos.config import Config, ConfigSource


def test_dump_directory_temp_dir():
    """Test DumpDirectory with TemporaryDirectory"""
    with TemporaryDirectory() as temp_dir_path:
        temp_dir = TemporaryDirectory()
        temp_dir.name = temp_dir_path  # set a known path for testing
        
        dump_dir: DumpDirectory = temp_dir
        
        assert dirname(dump_dir) == temp_dir_path


def test_dump_directory_path_string():
    """Test DumpDirectory with string path"""
    with tempfile.TemporaryDirectory() as temp_dir:
        dump_dir: DumpDirectory = Path(temp_dir)
        
        assert dirname(dump_dir) == temp_dir


def test_dump_directory_path_pathlib():
    """Test DumpDirectory with Path object"""
    with tempfile.TemporaryDirectory() as temp_dir:
        path_obj = Path(temp_dir)
        dump_dir: DumpDirectory = path_obj
        
        assert dirname(dump_dir) == str(path_obj)


def test_dirname_invalid_type():
    """Test that dirname with invalid type raises error"""
    with pytest.raises(ValueError, match="Unexpected dump directory type"):
        dirname("invalid_type")  # type: ignore


def test_config_has_dump_smt_directory_field():
    """Test that Config has the new dump_smt_directory field"""
    config = Config(_parent=None, _source=ConfigSource.void)
    
    # Check that the field exists and defaults to None
    assert hasattr(config, 'dump_smt_directory')
    assert config.dump_smt_directory is None


def test_config_dump_smt_directory_accepts_string():
    """Test that dump_smt_directory accepts string values"""
    with tempfile.TemporaryDirectory() as temp_dir:
        config = Config(
            _parent=None, 
            _source=ConfigSource.void, 
            dump_smt_directory=temp_dir
        )
        
        assert config.dump_smt_directory == temp_dir