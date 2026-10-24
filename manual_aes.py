import secrets


BLOCK_SIZE = 16
EXPANDED_KEY_SIZE = 176
NUMBER_OF_ROUNDS = 10


class AESError(Exception):
    pass


def _rotate_left(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _gf_multiply(first: int, second: int) -> int:
    product = 0
    multiplicand = first
    multiplier = second
    for _ in range(8):
        if multiplier & 1:
            product ^= multiplicand
        high_bit_set = multiplicand & 0x80
        multiplicand = (multiplicand << 1) & 0xFF
        if high_bit_set:
            multiplicand ^= 0x1B
        multiplier >>= 1
    return product


def _gf_power(value: int, exponent: int) -> int:
    result = 1
    factor = value
    remaining_exponent = exponent
    while remaining_exponent:
        if remaining_exponent & 1:
            result = _gf_multiply(result, factor)
        factor = _gf_multiply(factor, factor)
        remaining_exponent >>= 1
    return result


def _multiplicative_inverse(value: int) -> int:
    if value == 0:
        return 0
    return _gf_power(value, 254)


def _generate_s_boxes() -> tuple[tuple[int, ...], tuple[int, ...]]:
    s_box_values: list[int] = []
    inverse_s_box_values = [0] * 256
    for value in range(256):
        inverse = _multiplicative_inverse(value)
        substituted = inverse ^ _rotate_left(inverse, 1) ^ _rotate_left(inverse, 2)
        substituted ^= _rotate_left(inverse, 3) ^ _rotate_left(inverse, 4) ^ 0x63
        s_box_values.append(substituted)
        inverse_s_box_values[substituted] = value
    return tuple(s_box_values), tuple(inverse_s_box_values)


S_BOX, INV_S_BOX = _generate_s_boxes()
if S_BOX[0x00] != 0x63 or S_BOX[0x53] != 0xED:
    raise AESError("invalid AES substitution tables")


def encrypt_block(key: bytes, block: bytes) -> bytes:
    _validate_block(block)
    round_keys = _expand_key(key)
    state = _add_round_key(list(block), round_keys[0])

    for round_index in range(1, NUMBER_OF_ROUNDS):
        state = _substitute_bytes(state, S_BOX)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[round_index])

    state = _substitute_bytes(state, S_BOX)
    state = _shift_rows(state)
    return bytes(_add_round_key(state, round_keys[NUMBER_OF_ROUNDS]))


def decrypt_block(key: bytes, block: bytes) -> bytes:
    _validate_block(block)
    round_keys = _expand_key(key)
    state = _add_round_key(list(block), round_keys[NUMBER_OF_ROUNDS])

    for round_index in range(NUMBER_OF_ROUNDS - 1, 0, -1):
        state = _inverse_shift_rows(state)
        state = _substitute_bytes(state, INV_S_BOX)
        state = _add_round_key(state, round_keys[round_index])
        state = _inverse_mix_columns(state)

    state = _inverse_shift_rows(state)
    state = _substitute_bytes(state, INV_S_BOX)
    return bytes(_add_round_key(state, round_keys[0]))


def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    _validate_key(key)
    _validate_block(iv)
    _require_bytes(plaintext)
    padded_plaintext = _apply_pkcs7_padding(plaintext)
    previous_block = iv
    encrypted_blocks: list[bytes] = []

    for plaintext_block in _split_blocks(padded_plaintext):
        encrypted_block = encrypt_block(key, _xor_blocks(plaintext_block, previous_block))
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return b"".join(encrypted_blocks)


def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    _validate_key(key)
    _validate_block(iv)
    _require_bytes(ciphertext)
    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise AESError("invalid AES ciphertext")

    previous_block = iv
    decrypted_blocks: list[bytes] = []
    for ciphertext_block in _split_blocks(ciphertext):
        decrypted_block = _xor_blocks(decrypt_block(key, ciphertext_block), previous_block)
        decrypted_blocks.append(decrypted_block)
        previous_block = ciphertext_block

    return _remove_pkcs7_padding(b"".join(decrypted_blocks))


def generate_iv() -> bytes:
    return secrets.token_bytes(BLOCK_SIZE)


def expand_key(key: bytes) -> tuple[bytes, ...]:
    return _expand_key(key)


def sub_bytes(block: bytes) -> bytes:
    _validate_block(block)
    return bytes(_substitute_bytes(list(block), S_BOX))


def inv_sub_bytes(block: bytes) -> bytes:
    _validate_block(block)
    return bytes(_substitute_bytes(list(block), INV_S_BOX))


def shift_rows(block: bytes) -> bytes:
    _validate_block(block)
    return bytes(_shift_rows(list(block)))


def inv_shift_rows(block: bytes) -> bytes:
    _validate_block(block)
    return bytes(_inverse_shift_rows(list(block)))


def mix_columns(block: bytes) -> bytes:
    _validate_block(block)
    return bytes(_mix_columns(list(block)))


def inv_mix_columns(block: bytes) -> bytes:
    _validate_block(block)
    return bytes(_inverse_mix_columns(list(block)))


def _expand_key(key: bytes) -> tuple[bytes, ...]:
    _validate_key(key)
    words = [list(key[index : index + 4]) for index in range(0, BLOCK_SIZE, 4)]
    round_constant = 1

    for word_index in range(4, 44):
        temporary_word = words[word_index - 1].copy()
        if word_index % 4 == 0:
            temporary_word = _substitute_word(_rotate_word(temporary_word))
            temporary_word[0] ^= round_constant
            round_constant = _gf_multiply(round_constant, 2)
        words.append(_xor_word(words[word_index - 4], temporary_word))

    expanded_key = b"".join(bytes(word) for word in words)
    if len(expanded_key) != EXPANDED_KEY_SIZE:
        raise AESError("invalid AES internal state")
    return tuple(
        expanded_key[index : index + BLOCK_SIZE]
        for index in range(0, EXPANDED_KEY_SIZE, BLOCK_SIZE)
    )


def _substitute_word(word: list[int]) -> list[int]:
    return [S_BOX[value] for value in word]


def _rotate_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def _xor_word(first: list[int], second: list[int]) -> list[int]:
    return [first[index] ^ second[index] for index in range(4)]


def _substitute_bytes(state: list[int], substitution_box: tuple[int, ...]) -> list[int]:
    return [substitution_box[value] for value in state]


def _shift_rows(state: list[int]) -> list[int]:
    return [state[row + 4 * ((column + row) % 4)] for column in range(4) for row in range(4)]


def _inverse_shift_rows(state: list[int]) -> list[int]:
    return [state[row + 4 * ((column - row) % 4)] for column in range(4) for row in range(4)]


def _mix_columns(state: list[int]) -> list[int]:
    mixed_state: list[int] = []
    for column_start in range(0, BLOCK_SIZE, 4):
        first, second, third, fourth = state[column_start : column_start + 4]
        mixed_state.extend(
            (
                _gf_multiply(first, 2) ^ _gf_multiply(second, 3) ^ third ^ fourth,
                first ^ _gf_multiply(second, 2) ^ _gf_multiply(third, 3) ^ fourth,
                first ^ second ^ _gf_multiply(third, 2) ^ _gf_multiply(fourth, 3),
                _gf_multiply(first, 3) ^ second ^ third ^ _gf_multiply(fourth, 2),
            )
        )
    return mixed_state


def _inverse_mix_columns(state: list[int]) -> list[int]:
    mixed_state: list[int] = []
    for column_start in range(0, BLOCK_SIZE, 4):
        first, second, third, fourth = state[column_start : column_start + 4]
        mixed_state.extend(
            (
                _gf_multiply(first, 14)
                ^ _gf_multiply(second, 11)
                ^ _gf_multiply(third, 13)
                ^ _gf_multiply(fourth, 9),
                _gf_multiply(first, 9)
                ^ _gf_multiply(second, 14)
                ^ _gf_multiply(third, 11)
                ^ _gf_multiply(fourth, 13),
                _gf_multiply(first, 13)
                ^ _gf_multiply(second, 9)
                ^ _gf_multiply(third, 14)
                ^ _gf_multiply(fourth, 11),
                _gf_multiply(first, 11)
                ^ _gf_multiply(second, 13)
                ^ _gf_multiply(third, 9)
                ^ _gf_multiply(fourth, 14),
            )
        )
    return mixed_state


def _add_round_key(state: list[int], round_key: bytes) -> list[int]:
    return [value ^ round_key[index] for index, value in enumerate(state)]


def _apply_pkcs7_padding(plaintext: bytes) -> bytes:
    padding_length = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    return plaintext + bytes((padding_length,)) * padding_length


def _remove_pkcs7_padding(padded_plaintext: bytes) -> bytes:
    padding_length = padded_plaintext[-1]
    if not 1 <= padding_length <= BLOCK_SIZE:
        raise AESError("invalid AES padding")
    if padded_plaintext[-padding_length:] != bytes((padding_length,)) * padding_length:
        raise AESError("invalid AES padding")
    return padded_plaintext[:-padding_length]


def _split_blocks(data: bytes) -> tuple[bytes, ...]:
    return tuple(data[index : index + BLOCK_SIZE] for index in range(0, len(data), BLOCK_SIZE))


def _xor_blocks(first: bytes, second: bytes) -> bytes:
    return bytes(first[index] ^ second[index] for index in range(BLOCK_SIZE))


def _validate_key(key: bytes) -> None:
    _require_bytes(key)
    if len(key) != BLOCK_SIZE:
        raise AESError("invalid AES input length")


def _validate_block(block: bytes) -> None:
    _require_bytes(block)
    if len(block) != BLOCK_SIZE:
        raise AESError("invalid AES input length")


def _require_bytes(value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError("AES inputs must be bytes")
