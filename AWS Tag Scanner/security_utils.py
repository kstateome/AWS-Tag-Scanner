"""
Security utility functions for file validation and data sanitization.

This module provides security-focused functions to prevent common vulnerabilities:
- Path traversal attacks
- CSV injection
- Oversized file processing
- Invalid JSON handling
"""

import os
import json
from typing import Dict, Any
from pathlib import Path


def validate_file_path(file_path: str, max_size_mb: int = 100) -> str:
    """
    Validate file path to prevent path traversal attacks.

    @param file_path: Path to validate
    @param max_size_mb: Maximum allowed file size in MB
    @return: Absolute validated path
    @raises ValueError: If path is invalid, missing, not a file, or too large
    """
    if not file_path:
        raise ValueError("File path cannot be empty")

    # Convert to absolute path
    abs_path = os.path.abspath(file_path)

    # Check if file exists
    if not os.path.exists(abs_path):
        raise ValueError(f"File not found: {file_path}")

    # Check if it's a file (not directory)
    if not os.path.isfile(abs_path):
        raise ValueError(f"Path is not a file: {file_path}")

    # Check file size
    file_size = os.path.getsize(abs_path)
    max_bytes = max_size_mb * 1024 * 1024
    if file_size > max_bytes:
        raise ValueError(f"File too large: {file_size} bytes (max: {max_bytes})")

    return abs_path


def validate_output_filename(filename: str) -> str:
    """
    Validate a user-supplied output filename (no path traversal, no absolute paths).

    - Disallow path separators and absolute paths
    - Disallow parent-directory segments
    Returns the sanitized filename (as a string)
    Raises ValueError on invalid names
    """
    if not filename:
        raise ValueError("Filename cannot be empty")

    p = Path(filename)

    # Disallow absolute paths
    if p.is_absolute():
        raise ValueError("Absolute paths are not allowed for output filename")

    # Disallow parent directory traversal
    if '..' in p.parts:
        raise ValueError("Parent directory traversal is not allowed in filename")

    # Disallow any path separators by ensuring it has only a name
    if len(p.parts) != 1:
        raise ValueError("Filename must not contain path separators")

    # Basic cleanliness: remove surrounding whitespace
    clean = p.name.strip()
    if not clean:
        raise ValueError("Filename must contain visible characters")

    return clean


def load_json_safely(file_path: str, max_size_mb: int = 10) -> Dict[str, Any]:
    """
    Load JSON file with security validations
    
    Args:
        file_path: Path to JSON file
        max_size_mb: Maximum allowed file size in MB
        
    Returns:
        Parsed JSON data
        
    Raises:
        ValueError: If file is invalid or too large
    """
    # Validate file path
    validated_path = validate_file_path(file_path, max_size_mb)
    
    # Load and parse JSON
    try:
        with open(validated_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")
    except UnicodeDecodeError as e:
        raise ValueError(f"Invalid file encoding: {e}")
    
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object")
    
    return data


def sanitize_csv_value(value: Any) -> Any:
    """
    Sanitize value to prevent CSV injection attacks
    
    Prefixes dangerous characters with single quote to prevent
    formula execution in Excel/LibreOffice/Google Sheets
    
    Args:
        value: Value to sanitize
        
    Returns:
        Sanitized value safe for CSV export
    """
    if not value or not isinstance(value, str):
        return value
    
    # Characters that could trigger formula execution
    dangerous_chars = ['=', '+', '-', '@', '\t', '\r', '\n']
    
    # If value starts with dangerous character, prefix with single quote
    if value and value[0] in dangerous_chars:
        return "'" + value
    
    return value
