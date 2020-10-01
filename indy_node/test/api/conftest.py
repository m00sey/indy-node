import pytest

def pytest_collection_modifyitems(items):
    for item in items:
        if "reply" in item.nodeid:
            item.add_marker(pytest.mark.api)

