from datetime import datetime

import pytest
from stp_core.loop.eventually import eventually
from indy_node.server.upgrade_log import UpgradeLogData
from indy_node.server.upgrader import Upgrader
import functools

whitelist = ['Failed to upgrade node',
             'failed upgrade',
             'This problem may have external reasons, check syslog for more information']


@pytest.mark.upgrade
def test_timeout_works(nodeSet, looper, monkeypatch, tconf):
    """
    Checks that after some timeout upgrade is marked as failed if
    it not started
    """
    async def mock(*x):
        return None

    # patch get_timeout not to wait one whole minute
    monkeypatch.setattr(Upgrader, 'get_timeout', lambda self, timeout: timeout)
    # patch _open_connection_and_send to make node think it sent upgrade
    # successfully
    monkeypatch.setattr(Upgrader, '_open_connection_and_send', mock)
    pending = {node.name for node in nodeSet}
    version = '1.5.1'
    timeout = 1

    def chk():
        nonlocal pending
        assert len(pending) == 0

    def upgrade_failed_callback_test(nodeName):
        nonlocal pending
        pending.remove(nodeName)

    ev_data = UpgradeLogData(datetime.utcnow(), version, 'some_id', tconf.UPGRADE_ENTRY)
    for node in nodeSet:
        monkeypatch.setattr(
            node.upgrader,
            '_actionFailedCallback',
            functools.partial(
                upgrade_failed_callback_test,
                node.name))
        looper.run(node.upgrader._sendUpgradeRequest(ev_data, timeout))

    looper.run(eventually(chk))
