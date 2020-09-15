from collections import OrderedDict

import pytest

from indy_common.types import ClientGetRichSchemaObjectByIdOperation
from plenum.common.messages.fields import ConstantField, NonEmptyStringField

EXPECTED_ORDERED_FIELDS = OrderedDict([
    ("type", ConstantField),
    ("id", NonEmptyStringField),
])


@pytest.mark.types
def test_has_expected_fields():
    actual_field_names = OrderedDict(ClientGetRichSchemaObjectByIdOperation.schema).keys()
    assert actual_field_names == EXPECTED_ORDERED_FIELDS.keys()


@pytest.mark.types
def test_has_expected_validators():
    schema = dict(ClientGetRichSchemaObjectByIdOperation.schema)
    for field, validator in EXPECTED_ORDERED_FIELDS.items():
        assert isinstance(schema[field], validator)
