import pytest

def pytest_collection_modifyitems(items):
    for item in items:
        if "suspension" in item.nodeid:
            item.add_marker(pytest.mark.suspension)

