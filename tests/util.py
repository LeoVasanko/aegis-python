import random


_rng = random.SystemRandom()


def random_split_bytes(data: bytes) -> list[bytes]:
    """Split ``data`` into one to a few random-sized chunks.

    Keeps chunk sizes positive and varies the number of pieces between 1 and 4.
    """
    if not data:
        return [data]
    if len(data) == 1:
        return [data]

    max_chunks = min(4, len(data))
    chunks = _rng.randint(1, max_chunks)
    if chunks == 1:
        return [data]

    cut_points = sorted(_rng.sample(range(1, len(data)), chunks - 1))
    start = 0
    parts = []
    for stop in (*cut_points, len(data)):
        parts.append(data[start:stop])
        start = stop
    return parts
