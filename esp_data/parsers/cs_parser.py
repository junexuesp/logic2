"""
BLE 6.0 Channel Sounding (CS) packet parser.

This project uses sequence-only CS input (no AA, no Trailer in HLA input):
  Sounding Sequence (32 or 96) or Random Sequence (32/64/96/128).
"""

from constants import (
    CS_MARKER_PATTERNS,
    CS_RANDOM_LENS,
    CS_SOUNDING_LENS,
)


def format_bits(bits, group=4):
    """
    Format bits as a binary string (transmission order, LSB first).
    Insert spaces every `group` bits so Logic 2 bubbles stay readable.
    """
    raw = ''.join(str(b & 1) for b in bits)
    if group <= 0 or len(raw) <= group:
        return raw
    return ' '.join(raw[i:i + group] for i in range(0, len(raw), group))


def _byte_from_lsb_bits(bits):
    """Convert up to 8 bits (LSB-first) into one byte value."""
    value = 0
    for idx, bit in enumerate(bits[:8]):
        value |= (bit & 1) << idx
    return value


def format_bytes_from_bits(bits):
    """
    Format bits as byte values in reception order.

    Each byte is assembled from 8 bits in transmission order (LSB-first per byte),
    then displayed as two-digit hex.
    """
    if not bits:
        return ''
    out = []
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            out.append(f'{_byte_from_lsb_bits(chunk):02X}?')
        else:
            out.append(f'{_byte_from_lsb_bits(chunk):02X}')
    return ' '.join(out)


def _alternating_base(bit_index):
    """Sounding sequence base: alternating 0/1 starting with 0 at bit 0."""
    return bit_index & 1


def _matches_sounding_pattern(bits):
    """
    Heuristic: sounding sequence is alternating 0/1 with up to two 4-bit markers
    (1100 or 0011) overwriting the base pattern.
    """
    if not bits:
        return False
    if len(bits) not in CS_SOUNDING_LENS:
        return False

    mismatches = []
    for idx, bit in enumerate(bits):
        if bit != _alternating_base(idx):
            mismatches.append(idx)

    if not mismatches:
        return True

    regions = []
    start = mismatches[0]
    prev = start
    for idx in mismatches[1:]:
        if idx == prev + 1:
            prev = idx
            continue
        regions.append((start, prev))
        start = idx
        prev = idx
    regions.append((start, prev))

    if len(regions) > 2:
        return False

    for begin, end in regions:
        span = end - begin + 1
        if span != 4:
            return False
        pattern = tuple(bits[begin:end + 1])
        if pattern not in CS_MARKER_PATTERNS:
            return False

    return True


def classify_optional_sequence(bits):
    """
    Classify sequence bits.

    Returns:
        (seq_type, seq_len) where seq_type is 'sounding' or 'random'.
    """
    if not bits:
        return 'random', 0
    if _matches_sounding_pattern(bits):
        return 'sounding', len(bits)
    if len(bits) in CS_RANDOM_LENS:
        return 'random', len(bits)
    if len(bits) in CS_SOUNDING_LENS:
        return 'sounding', len(bits)
    alt_matches = sum(
        1 for idx, bit in enumerate(bits) if bit == _alternating_base(idx)
    )
    if alt_matches >= max(1, int(len(bits) * 0.75)):
        return 'sounding', len(bits)
    return 'random', len(bits)


def cs_packet_complete(total_bits):
    """
    True if collected sequence length is legal:
      sounding: 32/96, random: 32/64/96/128.
    """
    return total_bits in CS_SOUNDING_LENS or total_bits in CS_RANDOM_LENS


def parse_cs_sync_bits(bits, rate, incomplete=False):
    """
    Parse collected CS_SYNC bits (sequence-only input).

    Args:
        bits: Sequence bits (transmission order, LSB first).
        rate: Detected bit-rate index (0=1M, 1=2M, ...).
        incomplete: True if collection ended due to timeout/gap mid-field.

    Returns:
        dict: Parsed CS_SYNC fields for AnalyzerFrame.data
    """
    result = {
        'packet_type': 'CS_SYNC',
        'phy': 'LE_2M' if rate == 1 else 'LE_1M',
        'total_bits': len(bits),
    }

    if len(bits) == 0:
        result['incomplete'] = True
        result['expected_bits'] = 32
        result['received_bits'] = len(bits)
        result['summary'] = "CS_SYNC incomplete 0/32 bits"
        return result

    seq_type, seq_len = classify_optional_sequence(bits)
    summary_parts = [
        'CS_SYNC',
        result['phy'],
    ]

    if seq_type == 'sounding':
        result['sequence_type'] = 'sounding'
        result['sounding_sequence'] = format_bits(bits)
        result['sounding_len'] = seq_len
        summary_parts.append(f"SS[{seq_len}]={result['sounding_sequence']}")
    else:
        result['sequence_type'] = 'random'
        result['random_sequence'] = format_bytes_from_bits(bits)
        result['random_bits'] = format_bits(bits)
        result['random_len'] = seq_len
        summary_parts.append(f"RS[{seq_len}]={result['random_sequence']}")

    # incomplete only if we stopped mid-field (not a legal complete length)
    if incomplete and not cs_packet_complete(len(bits)):
        result['incomplete'] = True
        summary_parts.append('incomplete')

    result['summary'] = ' | '.join(summary_parts)
    return result


def build_tone_frame_data(duration_us=None):
    """Build display fields for an unmodulated CS tone period."""
    return {
        'packet_type': 'CS_TONE',
        'duration_us': round(duration_us, 3) if duration_us is not None else 0,
    }
