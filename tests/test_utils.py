import pytest
from AWSTagScanner import validate_output_filename, sanitize_csv_value


def test_validate_output_filename_ok():
    assert validate_output_filename('file') == 'file'
    assert validate_output_filename('report.csv') == 'report.csv'


def test_validate_output_filename_bad():
    with pytest.raises(ValueError):
        validate_output_filename('..\secret')
    with pytest.raises(ValueError):
        validate_output_filename('subdir/file')
    with pytest.raises(ValueError):
        validate_output_filename('')


def test_sanitize_csv_value():
    assert sanitize_csv_value('=SUM(A1:A2)') == "'=SUM(A1:A2)"
    assert sanitize_csv_value('normal') == 'normal'
    assert sanitize_csv_value('') == ''
    assert sanitize_csv_value(None) is None
