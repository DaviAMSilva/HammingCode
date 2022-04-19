import argparse
import struct
import sys


class HammingCorrectionImpossible(Exception):
    """
    Exception raised when the hamming correction is impossible.
    """
    pass


def safe_str(message: str):
    """Make a string safe to print"""
    message = str(message)
    new_message = ""

    for char in message:
        if char.isprintable():
            new_message += char
        elif char == "\n":
            new_message += "\\n"
        else:
            new_message += "␀"

    return new_message


def check_bits(bits: str):
    for i in range(len(bits)):
        if bits[i] != "0" and bits[i] != "1":
            return False
    return True


def text_to_bits(text: str, separator: bool = False) -> str:
    result = ""
    for char in text:
        result += "{0:08b}".format(ord(char))
        if separator:
            result += "_"

    return result[:-1] if separator else result


def binary_to_bits(binary: bytes, separator: bool = False) -> str:
    result = ""
    for byte in binary:
        result += "{0:08b}".format(byte)
        if separator:
            result += "_"

    return result[:-1] if separator else result


def bits_to_text(bits: str) -> str:
    # remove 0's to the end of the message to make it a multiple of 8
    # because the bits in the message are stored in groups of 8 bits
    # anything after the last full byte is irrelevant
    while len(bits) % 8 != 0 and bits[-1] == "0":
        bits = bits[:-1]

    return "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))


def bits_to_binary(bits: str) -> bytes:
    # remove 0's to the end of the message to make it a multiple of 8
    # because the bits in the message are stored in groups of 8 bits
    # anything after the last full byte is irrelevant
    while len(bits) % 8 != 0 and bits[-1] == "0":
        bits = bits[:-1]

    return bytes([int(bits[i:i+8], 2) for i in range(0, len(bits), 8)])


def hamming_encode(message: str, verbose: bool = False) -> str:
    """Encodes the message using the hamming code

    Args:
        message (str): A string of bits to encode using the hamming code
        verbose (bool, optional): Print verbose. Defaults to False.

    Returns:
        str: A string of bits representing the encoded message
    """

    if (check_bits(message) == False):
        raise ValueError("The message must be a string of 0's and 1's")

    message = list(message)
    result = []

    # adding the message bits but skip parity bits i.e. every power of 2
    message_i = 0
    result_i = 0
    while message_i < len(message):
        if (result_i & result_i - 1):
            result += message[message_i]
            message_i += 1
        else:
            result += "0"
        result_i += 1

    # calculating the xor of all bits
    xor = 0
    for result_i in range(len(result)):
        if (result[result_i] == "1"):
            xor ^= result_i

    # adding the parity bits using the xor bits
    bit = 1
    while bit < len(result):
        if (xor & bit):
            result[bit] = "1"
        else:
            result[bit] = "0"
        bit <<= 1

    # global parity bit
    result[0] = str(result.count("1") % 2)

    if verbose:
        print("\nENCODE")
        print("xor:", xor, "(" + "{0:08b}".format(xor) + ")")
        print("parity", result.count("1") % 2)
        print("encoded:", "".join(result))

    return "".join(result)


def hamming_decode(message: str, verbose: bool = False) -> str:
    """A function to decode a message encoded using the hamming code

    Args:
        message (str): A string of bits to decode encoded using the hamming code
        verbose (bool, optional): Print verbose. Defaults to False.

    Returns:
        str: A string of bits representing the decoded message
    """

    if (check_bits(message) == False):
        raise ValueError("The message must be a string of 0's and 1's")

    result = ""

    # verify and correct the message beforehand if possible
    message = hamming_correct(message, verbose)

    # removing the parity bits
    for i, bit in enumerate(message):
        if i & i - 1:
            result += bit

    if verbose:
        print("\nDECODE")
        print("decoded:", result)

    return result


def hamming_verify(message: str, verbose: bool = False) -> tuple:
    """Verifies the integrity of a message encoded using the hamming code

    Args:
        message (str): A string of bits to verify encoded using the hamming code
        verbose (bool, optional): Print Verbose. Defaults to False.

    Returns:
        tuple: Format: (e:int, p:int) where e is the error count and p is the parity bit
            0 error:      (0, -1)
            1 error:      (1, {error position})
            2 errors:     (2, -1)
            parity error: (-1, -1)
    """

    if (check_bits(message) == False):
        raise ValueError("The message must be a string of 0's and 1's")

    # calculating the xor of all bits to find the error position
    xor = 0
    for i, bit in enumerate(message):
        if bit == "1":
            xor ^= i

    # if global parity is 0 then the message is (supposedly) correct
    parity = message.count("1") % 2

    if verbose:
        print("\nVERIFY")
        print("xor:", xor, "(" + "{0:08b}".format(xor) + ")")
        print("parity:", parity)

    if xor == 0:
        if parity == 0:
            return 0, -1
        else:
            return -1, -1
    else:
        if parity == 0:
            # if the global parity is 0 then there were 2 bit flips
            return 2, -1
        else:
            return 1, xor


def hamming_correct(message: str, verbose: bool = False) -> str:
    """Corrects the message using the hamming code

    Args:
        message (str): A string of bits to correct encoded using the hamming code
        verbose (bool, optional): Print verbose. Defaults to False.

    Raises:
        HammingCorrectionImpossible: If the message is not possible to correct

    Returns:
        str: The corrected message
    """

    if (check_bits(message) == False):
        raise ValueError("The message must be a string of 0's and 1's")

    errors, index = hamming_verify(message, verbose)

    if errors == 0:
        result = message
    elif errors == 1:
        message = list(message)
        message[index] = "0" if message[index] == "1" else "1"
        result = "".join(message)
    elif errors == 2:
        raise HammingCorrectionImpossible(
            "There are 2 (4, 6, ...) bit flips in the message")
    elif errors == -1:
        raise HammingCorrectionImpossible("The message parity is not correct")

    if verbose:
        print("\nCORRECT")
        print("index:", index, "(" + "{0:08b}".format(index) + ")")
        print("corrected:", "".join(result))

    return result


if __name__ == "__main__":
    # arguments: mode, message, input-mode, output-mode, input-file, output-file, verbose
    parser = argparse.ArgumentParser(description="HammingCode")
    parser.add_argument("mode", help="Mode: encode, decode or verify", choices=[
                        "encode", "decode", "verify"])
    parser.add_argument("message", nargs="?", help="Message to encode/decode")
    parser.add_argument("-im", "--input-mode", help="Input mode: bits, text, binary",
                        choices=["bits", "text", "binary"], default="text")
    parser.add_argument("-om", "--output-mode", help="Output mode: bits, text, binary",
                        choices=["bits", "text", "binary"], default="bits")
    parser.add_argument("-if", "--input-file", help="Input file")
    parser.add_argument("-of", "--output-file", help="Output file")
    parser.add_argument("-v", "--verbose", help="Print verbose",
                        action="store_true", default=False)
    args = parser.parse_args()

    mode = args.mode
    message = args.message
    input_mode = args.input_mode
    output_mode = args.output_mode
    input_file = args.input_file
    output_file = args.output_file
    verbose = args.verbose
    result = ""

    # verify output file can be written
    if output_file:
        try:
            open(output_file, "w").close()
        except IOError:
            print("Error: cannot write to output file")
            exit(1)

    # read the message from the file if specified
    if input_file:
        if input_mode == "bits" or input_mode == "text":
            read_mode = "r"
        elif input_mode == "binary":
            read_mode = "rb"

        with open(input_file, read_mode) as f:
            message = f.read()
    elif not message or message == "":
        message = input("Message: ")

    if not message or message == "" or message == bytes():
        raise ValueError("Error: No message provided")

    if verbose:
        print("ARGUMENTS")
        print("Mode: {}".format(mode))
        if input_mode == "bits":
            print("Bits: {}".format(safe_str(message)))
            print("Size: {}".format(len(message)))
        elif input_mode == "text":
            print("Text: {}".format(safe_str(message)))
            print("Text Size: {}".format(len(message)))
            print("Bits: {}".format(text_to_bits(message, True)))
            print("Bits Size: {}".format(len(text_to_bits(message))))
        elif input_mode == "binary":
            print("Binary: {}".format(safe_str(message)))
            print("Binary Size: {}".format(len(message)))
            print("Bits: {}".format(binary_to_bits(message, True)))
            print("Bits Size: {}".format(len(binary_to_bits(message))))
        print("Input mode: {}".format(input_mode))
        print("Output mode: {}".format(output_mode))
        if input_file:
            print("Input file: {}".format(input_file))
        if output_file:
            print("Output file: {}".format(output_file))

    # convert input to correct format
    if input_mode == "bits":
        if not check_bits(message):
            raise ValueError("Error: Input is not a bit string")
    elif input_mode == "text":
        message = text_to_bits(message)
    elif input_mode == "binary":
        message = binary_to_bits(message)

    # encode/decode/verify
    if mode == "encode":
        result = hamming_encode(message, verbose)
    elif mode == "decode":
        try:
            result = hamming_decode(message, verbose)
        except HammingCorrectionImpossible as e:
            print("\nEXCEPTION")
            print(e)
            exit(1)
    elif mode == "verify":
        errors, index = hamming_verify(message, verbose)
        if errors == 0:
            result = "No errors detected"
        elif errors == 1:
            result = "1 bit error detected at index {}".format(index)
        elif errors == 2:
            result = "2 (4, 6, ...) bit error(s) detected"
        elif errors == -1:
            result = "The message parity is not correct"

    # convert output to correct format
    if mode != "verify":
        if output_mode == "text":
            result = bits_to_text(result)
        elif output_mode == "binary":
            # add 0's to the end of the message to make it a multiple of 8
            while len(result) % 8 != 0:
                result += "0"

            result = bits_to_binary(result)

    # write the result to the file if specified
    if output_file:
        if verbose:
            print("\nOUTPUT")
            print("Output:", safe_str(result))

        if output_mode == "bits" or output_mode == "text":
            write_mode = "w"
        elif output_mode == "binary":
            write_mode = "wb"

        with open(output_file, write_mode) as f:
            f.write(result)
    else:
        print("Result: ", safe_str(result))
