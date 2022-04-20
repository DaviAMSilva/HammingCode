import os

import pytest

from hamming import (HammingCorrectionImpossible, __hamming_main,
                     binary_to_bits, bits_to_binary, bits_to_text,
                     hamming_correct, hamming_decode, hamming_encode,
                     hamming_verify, text_to_bits)

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
    index1 = 3

    corrupted1 = list(encoded)
    corrupted1[index1] = "0" if corrupted1[index1] == "1" else "1"
    corrupted1 = "".join(corrupted1)

    assert hamming_verify(corrupted1)[0] == 1
    assert hamming_verify(corrupted1)[1] == index1
    assert hamming_correct(corrupted1) == encoded

    # corrupt 2 bits
    index2 = 4
    index3 = 7

    corrupted2 = list(encoded)
    corrupted2[index2] = "0" if corrupted2[index2] == "1" else "1"
    corrupted2[index3] = "0" if corrupted2[index3] == "1" else "1"
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


def test_main_encode_decode():
    if not os.path.exists("test"):
        os.makedirs("test")

    # encode
    __hamming_main("encode", TEXT_MSG, "text", "bits",
                   "", "test/encoded.txt", True)

    # decode
    __hamming_main("decode", "", "bits", "text",
                   "test/encoded.txt", "test/result.txt", True)

    # verify the result
    with open("test/result.txt", "r") as f:
        result = f.read()

    assert result == TEXT_MSG


def test_main_binary():
    if not os.path.exists("test"):
        os.makedirs("test")

    # make a text file
    with open("test/test.txt", "w") as f:
        f.write(TEXT_MSG)

    # encode
    __hamming_main("encode", "", "text", "binary",
                   "test/test.txt", "test/test.bin", True)

    # decode
    __hamming_main("decode", "", "binary", "text",
                   "test/test.bin", "test/result.txt", True)

    # verify the result
    with open("test/result.txt", "r") as f:
        result = f.read()

    assert result == TEXT_MSG


def test_main_verify_correct():
    if not os.path.exists("test"):
        os.makedirs("test")

    # corrupt 0 bit
    with open("test/test.txt", "w") as f:
        f.write(TEXT_MSG_ENCODED)

    # verify
    __hamming_main("verify", "", "bits", "",
                   "test/test.txt", "test/verified.txt", True)

    # correct
    __hamming_main("correct", "", "bits", "bits",
                   "test/test.txt", "test/corrected.txt", True)

    with open("test/verified.txt", "r") as f:
        result = f.read()

    with open("test/corrected.txt", "r") as f:
        result2 = f.read()

    assert result == "0 bit error detected"
    assert result2 == TEXT_MSG_ENCODED

    # corrupt 1 bit
    index1 = 3
    corrupted1 = list(TEXT_MSG_ENCODED)
    corrupted1[index1] = "0" if corrupted1[index1] == "1" else "1"
    with open("test/test.txt", "w") as f:
        f.write("".join(corrupted1))

    # verify
    __hamming_main("verify", "", "bits", "",
                   "test/test.txt", "test/verified.txt", True)

    # correct
    __hamming_main("correct", "", "bits", "bits",
                   "test/test.txt", "test/corrected.txt", True)

    with open("test/verified.txt", "r") as f:
        result = f.read()

    with open("test/corrected.txt", "r") as f:
        result2 = f.read()

    assert result == "1 bit error detected at index " + str(index1)
    assert result2 == TEXT_MSG_ENCODED

    # corrupt 2 bits
    index2 = 4
    index3 = 7
    corrupted2 = list(TEXT_MSG_ENCODED)
    corrupted2[index2] = "0" if corrupted2[index2] == "1" else "1"
    corrupted2[index3] = "0" if corrupted2[index3] == "1" else "1"

    with open("test/test.txt", "w") as f:
        f.write("".join(corrupted2))

    # verify
    __hamming_main("verify", "", "bits", "",
                   "test/test.txt", "test/verified.txt", True)

    # correct
    with pytest.raises(HammingCorrectionImpossible):
        __hamming_main("correct", "", "bits", "",
                       "test/test.txt", "test/corrected.txt", True)

    with open("test/verified.txt", "r") as f:
        result = f.read()

    assert result == "2 (4, 6, ...) bit errors detected"

    # corrupt first bit
    corrupted3 = list(TEXT_MSG_ENCODED)
    corrupted3[0] = "0" if corrupted3[0] == "1" else "1"

    with open("test/test.txt", "w") as f:
        f.write("".join(corrupted3))

    # verify
    __hamming_main("verify", "", "bits", "",
                   "test/test.txt", "test/verified.txt", True)

    # correct
    with pytest.raises(HammingCorrectionImpossible):
        __hamming_main("correct", "", "bits", "",
                       "test/test.txt", "test/corrected.txt", True)

    with open("test/verified.txt", "r") as f:
        result = f.read()

    assert result == "The message parity is not correct"
