# pragma version ~=0.4.3

LIMIT: public(immutable(uint256))


@deploy
def __init__(limit: uint256):
    LIMIT = limit


@view
@external
def under(x: uint256) -> bool:
    return x <= LIMIT
