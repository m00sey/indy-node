import json
from base64 import b64encode
from binascii import hexlify
from hashlib import sha256

import pytest
from indy.did import create_and_store_my_did
from libnacl import randombytes
from libnacl.secret import SecretBox

from indy_node.test.helper import sdk_add_attribute_and_check
from plenum.common.exceptions import RequestRejectedException, RequestNackedException
from plenum.common.util import rawToFriendly, randomString
from plenum.test.pool_transactions.helper import sdk_add_new_nym


@pytest.mark.txn_validation
def testSendAttribSucceedsForExistingDest(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({'name': 'Alice'})
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)


@pytest.mark.txn_validation
def testSendAttribFailsForNotExistingDest(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    wh, _ = sdk_wallet_trustee
    seed = randomString(32)
    did, _ = looper.loop.run_until_complete(create_and_store_my_did(
        wh, json.dumps({'seed': seed})))

    parameters = json.dumps({'name': 'Alice'})
    with pytest.raises(RequestRejectedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, sdk_wallet_trustee,
                                    parameters, dest=did)
    e.match('dest should be added before adding attribute for it')


@pytest.mark.txn_validation
def testSendAttribSucceedsForRawWithCompoundAttr(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'dateOfBirth': {
            'year': 1984,
            'month': 5,
            'dayOfMonth': 23
        }
    })
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)


@pytest.mark.txn_validation
def testSendAttribSucceedsForRawWithNullifiedAttr(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'name': None
    })
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)


@pytest.mark.txn_validation
def testSendAttribSucceedsForRawWithEndpointWithHaContainingIpAddrAndPort(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.117.186:6321'
        }
    })
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)


@pytest.mark.txn_validation
def testSendAttribSucceedsForRawWithEndpointWithHaBeingNull(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': None
        }
    })
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)


@pytest.mark.txn_validation
def testSendAttribSucceedsForRawWithEndpointWithValidHaAndOtherProperties(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.117.186:6321',
            'name': 'SOV Agent',
            'description': 'The SOV agent.'
        }
    })
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)


@pytest.mark.txn_validation
def testSendAttribSucceedsForRawWithEndpointWithoutHaButWithOtherProperties(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'name': 'SOV Agent',
            'description': 'The SOV agent.'
        }
    })
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)


@pytest.mark.txn_validation
def testSendAttribSucceedsForRawWithEndpointWithoutProperties(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {}
    })
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)


@pytest.mark.txn_validation
def testSendAttribSucceedsForRawWithEndpointBeingNull(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': None
    })
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaIfIpAddrHasWrongFormat(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.117:6321'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint address')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaIfSomeIpComponentsAreNegative(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.-1.117.186:6321'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint address')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaIfSomeIpCompHigherThanUpperBound(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.256.186:6321'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint address')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaIfIpAddrIsEmpty(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': ':6321'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint address')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaIfPortIsNegative(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.117.186:-1'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint port')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaIfPortIsHigherThanUpperBound(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.117.186:65536'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint port')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaIfPortIsFloat(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.117.186:6321.5'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint port')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaIfPortHasWrongFormat(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.117.186:ninety'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint port')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaIfPortIsEmpty(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.117.186:'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint port')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaContainingIpAddrOnly(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '52.11.117.186'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint format')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaContainingPortOnly(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': '6321'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint format')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaContainingDomainNameAndPort(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': 'sovrin.org:6321'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint address')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaContainingDomainNameOnly(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': 'sovrin.org'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint format')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaBeingHumanReadableText(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': 'This is not a host address.'
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint format')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithHaBeingDecimalNumber(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': 42
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('is not iterable')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointWithEmptyHa(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': {
            'ha': ''
        }
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('invalid endpoint format')


@pytest.mark.txn_validation
def testSendAttribFailsForRawWithEndpointBeingEmptyString(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'endpoint': ''
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match('should be a dict')


@pytest.mark.txn_validation
def testSendAttribFailsIfRawContainsMulipleAttrs(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({
        'name': 'Alice',
        'dateOfBirth': '05/23/2017'
    })
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match(' should contain one attribute')


@pytest.mark.txn_validation
def testSendAttribFailsIfRawContainsNoAttrs(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = json.dumps({})
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters)
    e.match(' should contain one attribute')


@pytest.mark.txn_validation
def testSendAttribSucceedsForHexSha256Hash(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    raw = json.dumps({
        'name': 'Alice'
    })

    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                xhash=sha256(raw.encode()).hexdigest())


@pytest.mark.txn_validation
def testSendAttribSucceedsForHexHashWithLettersInBothCases(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                xhash='6d4a333838d0ef96756cccC680AF2531075C512502Fb68c5503c63d93de859b3')


@pytest.mark.txn_validation
def testSendAttribFailsForHashShorterThanSha256(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    xhash=hexlify(randombytes(31)).decode())
    e.match('not a valid hash')


@pytest.mark.txn_validation
def testSendAttribFailsForHashLongerThanSha256(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    xhash=hexlify(randombytes(33)).decode())
    e.match('not a valid hash')


@pytest.mark.txn_validation
def testSendAttribFailsForBase58Hash(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    raw = json.dumps({
        'name': 'Alice'
    })
    hash = sha256(raw.encode()).digest()

    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    xhash=rawToFriendly(hash))
    e.match('not a valid hash')


@pytest.mark.txn_validation
def testSendAttribFailsForBase64Hash(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    raw = json.dumps({
        'name': 'Alice'
    })

    hash = sha256(raw.encode()).digest()
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    xhash=b64encode(hash).decode())
    e.match('not a valid hash')


@pytest.mark.txn_validation
def testSendAttribHasInvalidSyntaxIfHashIsEmpty(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    xhash='')
    e.match('not a valid hash')


@pytest.mark.txn_validation
def testSendAttribSucceedsForNonEmptyEnc(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    raw = json.dumps({
        'name': 'Alice'
    })
    secretBox = SecretBox()

    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                enc=secretBox.encrypt(raw.encode()).hex())


@pytest.mark.txn_validation
def testSendAttribHasInvalidSyntaxIfEncIsEmpty(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    enc='')
    e.match('empty string')


@pytest.mark.txn_validation
def testSendAttribHasInvalidSyntaxIfRawAndHashPassedAtSameTime(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    raw = json.dumps({
        'name': 'Alice'
    })

    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    xhash=sha256(raw.encode()).hexdigest(), enc=raw)
    e.match('only one field from raw, enc, hash is expected')


@pytest.mark.txn_validation
def testSendAttribHasInvalidSyntaxIfRawAndEncPassedAtSameTime(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    raw = json.dumps({
        'name': 'Alice'
    })
    secretBox = SecretBox()

    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    xhash=secretBox.encrypt(raw.encode()).hex(), enc=raw)
    e.match('not a valid hash')


@pytest.mark.txn_validation
def testSendAttribHasInvalidSyntaxIfHashAndEncPassedAtSameTime(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    raw = json.dumps({
        'name': 'Alice'
    })

    secretBox = SecretBox()
    encryptedRaw = secretBox.encrypt(raw.encode())

    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = None
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    xhash=sha256(encryptedRaw).hexdigest(), enc=encryptedRaw.hex())
    e.match('only one field from raw, enc, hash is expected')


@pytest.mark.txn_validation
def testSendAttribHasInvalidSyntaxIfRawHashAndEncPassedAtSameTime(
        looper, sdk_pool_handle, sdk_wallet_trustee):
    raw = json.dumps({
        'name': 'Alice'
    })

    secretBox = SecretBox()
    encryptedRaw = secretBox.encrypt(raw.encode())
    new_wallet = sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_trustee)
    parameters = raw
    with pytest.raises(RequestNackedException) as e:
        sdk_add_attribute_and_check(looper, sdk_pool_handle, new_wallet, parameters,
                                    xhash=sha256(encryptedRaw).hexdigest(), enc=encryptedRaw.hex())
    e.match('only one field from raw, enc, hash is expected')
