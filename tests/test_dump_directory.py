import tempfile
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

from halmos.solve import DumpDirectory
from halmos.config import Config, ConfigSource


def test_dump_directory_from_temp_dir():
    """Test DumpDirectory.from_temp_dir creates correct wrapper"""
    with TemporaryDirectory() as temp_dir_path:
        temp_dir = TemporaryDirectory()
        temp_dir.name = temp_dir_path  # set a known path for testing
        
        dump_dir = DumpDirectory.from_temp_dir(temp_dir)
        
        assert dump_dir.name == temp_dir_path
        assert dump_dir._temp_dir == temp_dir
        assert dump_dir._path is None


def test_dump_directory_from_path_string():
    """Test DumpDirectory.from_path with string path"""
    with tempfile.TemporaryDirectory() as temp_dir:
        dump_dir = DumpDirectory.from_path(temp_dir)
        
        assert dump_dir.name == temp_dir
        assert dump_dir._temp_dir is None
        assert dump_dir._path == temp_dir


def test_dump_directory_from_path_pathlib():
    """Test DumpDirectory.from_path with Path object"""
    with tempfile.TemporaryDirectory() as temp_dir:
        path_obj = Path(temp_dir)
        dump_dir = DumpDirectory.from_path(path_obj)
        
        assert dump_dir.name == str(path_obj)
        assert dump_dir._temp_dir is None
        assert dump_dir._path == str(path_obj)


def test_dump_directory_uninitialized():
    """Test that uninitialized DumpDirectory raises error"""
    dump_dir = DumpDirectory()
    
    with pytest.raises(ValueError, match="DumpDirectory not properly initialized"):
        _ = dump_dir.name


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