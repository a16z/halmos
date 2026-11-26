# pragma version ~=0.4.3
"""
@title Counter with a bug
"""

count: public(uint256)


@external
def add(x: uint256):
    # bug: resets the counter instead of adding 13
    if x == 13:
        self.count = 0
        return
    self.count += x
