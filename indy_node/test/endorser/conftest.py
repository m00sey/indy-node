import pytest

def pytest_collection_modifyitems(items):
    for item in items:
        if "endorser" in item.nodeid:
            item.add_marker(pytest.mark.endorser)

