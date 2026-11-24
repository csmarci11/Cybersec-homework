from crypto.diffie_hellman import (
    P,
    G,
    generate_private_exponent,
    modular_pow,
    public_value,
    shared_secret,
    validate_peer_public,
)
import pytest


def test_modular_pow_matches_builtin():
    assert modular_pow(123456789, 987654321, 1000000007) == pow(
        123456789, 987654321, 1000000007
    )


def test_two_parties_derive_same_secret():
    alice = generate_private_exponent()
    bob = generate_private_exponent()
    alice_public = public_value(alice)
    bob_public = public_value(bob)
    assert shared_secret(alice, bob_public) == shared_secret(bob, alice_public)


@pytest.mark.parametrize("value", [0, 1, P - 1, P, P + 1])
def test_invalid_public_values_rejected(value):
    with pytest.raises(ValueError):
        validate_peer_public(value)
