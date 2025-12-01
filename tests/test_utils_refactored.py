import pytest

from awstag_utils import validate_output_filename, sanitize_csv_value


def test_validate_output_filename_ok():
    assert validate_output_filename('report') == 'report'
    assert validate_output_filename('report.csv') == 'report.csv'


@pytest.mark.parametrize('bad', ["../secret", '/abs/path', 'folder/name', '', '   '])
def test_validate_output_filename_bad(bad):
    with pytest.raises(ValueError):
        validate_output_filename(bad)


def test_sanitize_csv_value_none_and_safe():
    assert sanitize_csv_value(None) is None
    assert sanitize_csv_value('normal') == 'normal'


def test_sanitize_csv_value_dangerous_prefixes():
    assert sanitize_csv_value('=SUM(A1:A2)') == "'=SUM(A1:A2)" 
    assert sanitize_csv_value('+1') == "'+1"
    assert sanitize_csv_value('-1') == "'-1"
    assert sanitize_csv_value('@cmd') == "'@cmd"
