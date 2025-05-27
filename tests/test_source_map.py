import os
import tempfile

import pytest

from halmos.mapper import SourceFileMap


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    # Clean up temporary files
    for file in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, file))
    os.rmdir(temp_dir)


@pytest.fixture
def source_map(temp_dir):
    """Create a SourceFileMap instance with the temporary directory as root."""
    source_map = SourceFileMap()
    source_map.set_root(temp_dir)
    return source_map


def create_test_file(temp_dir: str, content: str) -> str:
    """Helper function to create a temporary test file with given content."""
    fd, path = tempfile.mkstemp(dir=temp_dir)
    with os.fdopen(fd, "wb") as f:
        f.write(content.encode("utf-8"))
    return path


def test_basic_line_number(source_map, temp_dir):
    """Test basic line number calculation."""
    content = "line1\nline2\nline3"
    filepath = create_test_file(temp_dir, content)

    # Test each line
    assert source_map.get_line_number(filepath, 0) == 1  # start of line1
    assert source_map.get_line_number(filepath, 5) == 1  # first newline
    assert source_map.get_line_number(filepath, 6) == 2  # start of line2
    assert source_map.get_line_number(filepath, 11) == 2  # second newline
    assert source_map.get_line_number(filepath, 12) == 3  # start of line3
    assert source_map.get_line_number(filepath, 17) == 3  # EOF


def test_empty_file(source_map, temp_dir):
    """Test line number calculation for an empty file."""
    filepath = create_test_file(temp_dir, "")
    assert source_map.get_line_number(filepath, 0) is None  # EOF


def test_single_line(source_map, temp_dir):
    """Test line number calculation for a single line file."""
    content = "single line"
    filepath = create_test_file(temp_dir, content)
    assert source_map.get_line_number(filepath, 0) == 1
    assert source_map.get_line_number(filepath, 10) == 1  # last character
    assert source_map.get_line_number(filepath, 11) == 1  # EOF


def test_multiple_empty_lines(source_map, temp_dir):
    """Test line number calculation with multiple empty lines."""
    content = "\n\n\n"
    filepath = create_test_file(temp_dir, content)
    assert source_map.get_line_number(filepath, 0) == 1
    assert source_map.get_line_number(filepath, 1) == 2
    assert source_map.get_line_number(filepath, 2) == 3
    assert source_map.get_line_number(filepath, 3) == 3  # EOF


def test_unicode_content(source_map, temp_dir):
    """Test line number calculation with Unicode content."""
    content = "∎∎\nline2\n∎∎3"
    filepath = create_test_file(temp_dir, content)
    assert source_map.get_line_number(filepath, 0) == 1  # start of first line
    assert source_map.get_line_number(filepath, 6) == 1  # first \n
    assert source_map.get_line_number(filepath, 7) == 2  # start of second line
    assert source_map.get_line_number(filepath, 12) == 2  # second \n
    assert source_map.get_line_number(filepath, 13) == 3  # start of third line
    assert source_map.get_line_number(filepath, 14) == 3  # EOF


def test_windows_line_endings(source_map, temp_dir):
    """Test line number calculation with Windows-style line endings (CRLF)."""
    content = "line1\r\nline2\r\nline3"
    filepath = create_test_file(temp_dir, content)

    # Test each line
    assert source_map.get_line_number(filepath, 0) == 1  # start of line1
    assert source_map.get_line_number(filepath, 5) == 1  # first \r
    assert source_map.get_line_number(filepath, 6) == 1  # first \n
    assert source_map.get_line_number(filepath, 7) == 2  # start of line2 (after \r\n)
    assert source_map.get_line_number(filepath, 12) == 2  # second \r
    assert source_map.get_line_number(filepath, 13) == 2  # second \n
    assert source_map.get_line_number(filepath, 14) == 3  # start of line3 (after \r\n)
    assert source_map.get_line_number(filepath, 19) == 3  # EOF


def test_mixed_line_endings(source_map, temp_dir):
    """Test line number calculation with mixed line endings (LF and CRLF)."""
    content = "line1\nline2\r\nline3\nline4\r\n"
    filepath = create_test_file(temp_dir, content)

    # Test each line
    assert source_map.get_line_number(filepath, 0) == 1  # Start of line1
    assert source_map.get_line_number(filepath, 5) == 1  # first \n
    assert source_map.get_line_number(filepath, 6) == 2  # Start of line2
    assert source_map.get_line_number(filepath, 11) == 2  # \r before second \n
    assert source_map.get_line_number(filepath, 12) == 2  # second \n
    assert source_map.get_line_number(filepath, 13) == 3  # Start of line3 (after \r\n)
    assert source_map.get_line_number(filepath, 18) == 3  # third \n
    assert source_map.get_line_number(filepath, 19) == 4  # Start of line4
    assert source_map.get_line_number(filepath, 24) == 4  # \r before fourth \n
    assert source_map.get_line_number(filepath, 25) == 4  # fourth \n
    assert source_map.get_line_number(filepath, 26) == 4  # EOF
