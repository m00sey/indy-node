import pytest

def pytest_collection_modifyitems(items):
    for item in items:
        if "attrib" in item.nodeid:
            item.add_marker(pytest.mark.attrib_txn)
        elif "attr" in item.nodeid:
            item.add_marker(pytest.mark.attrib_txn)

