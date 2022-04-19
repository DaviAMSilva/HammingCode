import os
import random

import pytest

from hamming import (HammingCorrectionImpossible, binary_to_bits,
                     bits_to_binary, bits_to_text, hamming_correct,
                     hamming_decode, hamming_encode, hamming_verify,
                     text_to_bits)

TEXT_MSG = "this is a test"
TEXT_MSG_ENCODED = "011001111010001100100001101001011110011001000000110100101110011000100000011000010010000001110100011001010111001101110100"

BITS_MSG = "1010111"
BITS_MSG_ENCODED = "010110101111"

def test_encode():
    encoded = hamming_encode(text_to_bits(TEXT_MSG))
    assert encoded == TEXT_MSG_ENCODED

    encoded = hamming_encode(BITS_MSG)
    assert encoded == BITS_MSG_ENCODED


def test_decode():
    decoded = hamming_decode(TEXT_MSG_ENCODED)
    assert decoded == text_to_bits(TEXT_MSG)

    decoded = hamming_decode(BITS_MSG_ENCODED)
    assert decoded == BITS_MSG


def test_encode_decode():
    encoded = hamming_encode(text_to_bits(TEXT_MSG))
    decoded = bits_to_text(hamming_decode(encoded))
    assert TEXT_MSG == decoded

    encoded = hamming_encode(BITS_MSG)
    decoded = hamming_decode(encoded)
    assert BITS_MSG == decoded


def test_verify_correct():
    encoded = hamming_encode(text_to_bits(TEXT_MSG))

    # corrupt 0 bits
    assert hamming_verify(encoded)[0] == 0
    assert hamming_verify(encoded)[1] == -1
    assert hamming_correct(encoded) == encoded

    # corrupt 1 bits
    random_index = random.randint(1, len(encoded) - 1)

    corrupted1 = list(encoded)
    corrupted1[random_index] = "0" if corrupted1[random_index] == "1" else "1"
    corrupted1 = "".join(corrupted1)

    assert hamming_verify(corrupted1)[0] == 1
    assert hamming_verify(corrupted1)[1] == random_index
    assert hamming_correct(corrupted1) == encoded

    # corrupt 2 bits
    random_index1 = random.randint(1, len(encoded) - 1)
    random_index2 = random_index1

    while random_index2 == random_index1:
        random_index2 = random.randint(1, len(encoded) - 1)

    corrupted2 = list(encoded)
    corrupted2[random_index1] = "0" if corrupted2[random_index1] == "1" else "1"
    corrupted2[random_index2] = "0" if corrupted2[random_index2] == "1" else "1"
    corrupted2 = "".join(corrupted2)

    assert hamming_verify(corrupted2)[0] == 2
    assert hamming_verify(corrupted2)[1] == -1
    with pytest.raises(HammingCorrectionImpossible):
        hamming_correct(corrupted2)

    # corrupt first bit
    corrupted3 = list(encoded)
    corrupted3[0] = "0" if corrupted3[0] == "1" else "1"
    corrupted3 = "".join(corrupted3)

    assert hamming_verify(corrupted3)[0] == -1
    assert hamming_verify(corrupted3)[1] == -1
    with pytest.raises(HammingCorrectionImpossible):
        hamming_correct(corrupted3)
