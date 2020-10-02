import json
import pytest

from plenum.common.constants import NODE_IP, NODE_PORT, CLIENT_IP, CLIENT_PORT, ALIAS, VALIDATOR, SERVICES
from plenum.common.util import cryptonymToHex, hexToFriendly
from plenum.common.exceptions import RequestNackedException, RequestRejectedException

from plenum.test.helper import sdk_get_and_check_replies, sdk_get_bad_response, sdk_sign_request_strings, \
    sdk_send_signed_requests
from plenum.test.pool_transactions.helper import sdk_add_new_nym, prepare_node_request, \
    sdk_sign_and_send_prepared_request


@pytest.fixture(scope='function')
def node_request(looper, sdk_node_theta_added):
    sdk_steward_wallet, node = sdk_node_theta_added
    node_dest = hexToFriendly(node.nodestack.verhex)
    wh, did = sdk_steward_wallet
    node_request = looper.loop.run_until_complete(
        prepare_node_request(did, node.name, destination=node_dest,
                             nodeIp=node.nodestack.ha[0],
                             nodePort=node.nodestack.ha[1],
                             clientIp=node.clientstack.ha[0],
                             clientPort=node.clientstack.ha[1]))
    return json.loads(node_request)


def ensurePoolIsOperable(looper, sdk_pool_handle, sdk_wallet_creator):
    sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_creator)


@pytest.mark.node_txn
def testSendNodeFailsIfDestIsShortReadableName(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['dest'] = 'TheNewNode'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'b58 decoded value length 8 should be one of [16, 32]')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfDestIsHexKey(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['dest'] = cryptonymToHex(
        node_request['operation']['dest']).decode() + "0"
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'should not contain the following chars')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeHasInvalidSyntaxIfDestIsEmpty(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['dest'] = ''
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'b58 decoded value length 0 should be one of [16, 32]')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeHasInvalidSyntaxIfDestIsMissed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    del node_request['operation']['dest']
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'missed fields - dest')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodeIpContainsLeadingSpace(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_IP] = ' 122.62.52.13'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodeIpContainsTrailingSpace(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_IP] = '122.62.52.13 '
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))

    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodeIpHasWrongFormat(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_IP] = '122.62.52'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfSomeNodeIpComponentsAreNegative(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_IP] = '122.-1.52.13'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfSomeNodeIpComponentsAreHigherThanUpperBound(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_IP] = '122.62.256.13'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodeIpIsEmpty(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_IP] = ''
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodeIpIsMissed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    del node_request['operation']['data'][NODE_IP]
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'missed fields - node_ip')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodePortIsNegative(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_PORT] = -1
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'network port out of the range 0-65535')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodePortIsHigherThanUpperBound(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_PORT] = 65536
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'network port out of the range 0-65535')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodePortIsFloat(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_PORT] = 5555.5
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'expected types')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodePortHasWrongFormat(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_PORT] = 'ninety'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'expected types')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodePortIsEmpty(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][NODE_PORT] = ''
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'expected types ')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfNodePortIsMissed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    del node_request['operation']['data'][NODE_PORT]
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'missed fields - node_port')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientIpContainsLeadingSpace(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_IP] = ' 122.62.52.13'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientIpContainsTrailingSpace(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_IP] = '122.62.52.13 '
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientIpHasWrongFormat(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_IP] = '122.62.52'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfSomeClientIpComponentsAreNegative(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_IP] = '122.-1.52.13'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfSomeClientIpComponentsAreHigherThanUpperBound(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_IP] = '122.62.256.13'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientIpIsEmpty(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_IP] = ''
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid network ip address')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientIpIsMissed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    del node_request['operation']['data'][CLIENT_IP]
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'missed fields - client_ip')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientPortIsNegative(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_PORT] = -1
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'network port out of the range 0-65535')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientPortIsHigherThanUpperBound(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_PORT] = 65536
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'network port out of the range 0-65535')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientPortIsFloat(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_PORT] = 5555.5
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'expected types')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientPortHasWrongFormat(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_PORT] = 'ninety'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'expected types')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientPortIsEmpty(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][CLIENT_PORT] = ''
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'expected types')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfClientPortIsMissed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    del node_request['operation']['data'][CLIENT_PORT]
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'missed fields - client_port')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfAliasIsEmpty(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][ALIAS] = ''
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'empty string')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfAliasIsMissed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    del node_request['operation']['data'][ALIAS]
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'missed fields ')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfServicesContainsUnknownValue(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][SERVICES] = [VALIDATOR, 'DECIDER']
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'unknown value')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfServicesIsValidatorValue(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][SERVICES] = VALIDATOR  # just string, not array
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'expected types')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfServicesIsEmptyString(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][SERVICES] = ''
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'expected types')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeSuccessIfDataContainsUnknownField(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'][SERVICES] = []
    node_request['operation']['data']['extra'] = 42
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestRejectedException,
                         'action is not allowed')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfDataIsEmptyJson(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'] = {}
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'missed fields ')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfDataIsBrokenJson(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'] = "{'node_ip': '10.0.0.105', 'node_port': 9701"
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid type')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeFailsIfDataIsNotJson(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'] = 'not_json'
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid type')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeHasInvalidSyntaxIfDataIsEmptyString(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['data'] = ''
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid type')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeHasInvalidSyntaxIfDataIsMissed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    del node_request['operation']['data']
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'missed fields')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.skip(reason='INDY-1864')
def testSendNodeHasInvalidSyntaxIfUnknownParameterIsPassed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    node_request['operation']['albus'] = 'severus'
    steward_wallet, node = sdk_node_theta_added
    signed_reqs = sdk_sign_request_strings(looper, steward_wallet, [node_request])
    request_couple = sdk_send_signed_requests(sdk_pool_handle, signed_reqs)[0]
    sdk_get_and_check_replies(looper, [request_couple])
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeHasInvalidSyntaxIfAllParametersAreMissed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    for f in node_request['operation'].keys():
        node_request['operation'][f] = ''
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_bad_response(looper, [request_couple], RequestNackedException,
                         'invalid type')
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)


@pytest.mark.node_txn
def testSendNodeSucceedsIfServicesIsMissed(
        looper, sdk_pool_handle, nodeSet, sdk_node_theta_added, node_request):
    del node_request['operation']['data'][SERVICES]
    steward_wallet, node = sdk_node_theta_added
    request_couple = sdk_sign_and_send_prepared_request(looper, steward_wallet,
                                                        sdk_pool_handle,
                                                        json.dumps(node_request))
    sdk_get_and_check_replies(looper, [request_couple])
    ensurePoolIsOperable(looper, sdk_pool_handle, steward_wallet)
