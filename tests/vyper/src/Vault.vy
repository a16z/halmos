# pragma version ~=0.4.3

balanceOf: public(HashMap[address, uint256])
total: public(uint256)


@external
def deposit(amount: uint256):
    self.balanceOf[msg.sender] += amount
    self.total += amount


@external
def withdraw(amount: uint256):
    self.balanceOf[msg.sender] -= amount
    self.total -= amount


@external
def boom(x: uint256):
    assert x != 42, UNREACHABLE
