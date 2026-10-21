import asyncio

from tests.base_test_case import BaseTestCase

from electionguard.discrete_log import DiscreteLog, DiscreteLogNotFoundError
from electionguard.elgamal import elgamal_encrypt, elgamal_keypair_from_secret
from electionguard.group import ONE_MOD_Q, TWO_MOD_Q
from electionguard.utils import get_optional

# far beyond any value the rest of the suite decrypts, so it is never cached
UNCACHED_PLAINTEXT = 2_000_000


class TestDiscreteLog(BaseTestCase):
    """Discrete log singleton tests"""

    def test_settings_apply_to_library_decryption(self):
        # Arrange
        dlog = DiscreteLog.get_instance()
        dlog.set_lazy_evaluation(False)
        self.addCleanup(dlog.set_lazy_evaluation, True)
        keypair = get_optional(elgamal_keypair_from_secret(TWO_MOD_Q))
        ciphertext = get_optional(
            elgamal_encrypt(UNCACHED_PLAINTEXT, ONE_MOD_Q, keypair.public_key)
        )

        # Act & Assert
        with self.assertRaises(DiscreteLogNotFoundError):
            ciphertext.decrypt(keypair.secret_key)

    def test_precompute_cache_async_fills_instance_cache(self):
        # Arrange
        dlog = DiscreteLog.get_instance()
        exponent = max(dlog.get_cache().values()) + 10

        # Act
        asyncio.run(dlog.precompute_cache_async(exponent))

        # Assert
        self.assertEqual(max(dlog.get_cache().values()), exponent)
