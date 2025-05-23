from typing import Optional

class SourceMapping:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._id_to_filename: dict[int, str] = {}
            self._all_files: set[str] = set()
            self._initialized = True

    def add_mapping(self, file_id: int, filename: str) -> None:
        """Add a mapping from file ID to filename and track the filename."""
        self._id_to_filename[file_id] = filename
        self._all_files.add(filename)

    def get_filename(self, file_id: int) -> str | None:
        """Get filename for a given file ID."""
        return self._id_to_filename.get(file_id)

    def get_all_mappings(self) -> dict[int, str]:
        """Get all file ID to filename mappings."""
        return self._id_to_filename.copy()

    def get_all_files(self) -> set[str]:
        """Get the set of all tracked filenames."""
        return self._all_files.copy()

    def reset(self) -> None:
        """Reset all mappings and file list."""
        self._id_to_filename.clear()
        self._all_files.clear() 