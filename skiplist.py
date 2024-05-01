import math
import random


class Node:
    def __init__(self, *, start, chunk, level):
        self.start = start
        self.size = len(chunk) if chunk else None
        self.level = level
        self.chunk = chunk

        self.forward = [None] * (level + 1)


class SkipList:
    def __init__(self, max_level=4, p=0.5):
        self.max_level = max_level
        self.p = p
        self.header = Node(start=None, chunk=None, level=max_level)
        self.level = 0
        self.total_size = 0

    def _new_node(self, start, chunk, level=None):
        if level is None:
            level = self._random_level()

        return Node(start=start, chunk=chunk, level=level)

    def _random_level(self):
        return int(math.log(random.random(), 1 - self.p))

    def append(self, chunk):
        new_node = self._new_node(self.total_size, chunk)

        update = [None] * (self.max_level + 1)
        current = self.header

        for i in range(self.level, -1, -1):
            while current.forward[i] and current.forward[i].start < self.total_size:
                current = current.forward[i]
            update[i] = current

        new_level = new_node.level
        for i in range(new_level + 1):
            if i > self.level:
                self.header.forward[i] = new_node
            else:
                new_node.forward[i] = update[i].forward[i]
                update[i].forward[i] = new_node

        self.level = max(self.level, new_level)
        self.total_size += new_node.size

    def _find_node(self, index):
        """Find the node that contains the byte at the specified index."""
        current = self.header
        for i in range(self.level, -1, -1):
            while current.forward[i] and current.forward[i].start <= index:
                current = current.forward[i]
        assert current.start <= index
        assert current.chunk is not None
        return current

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(self.total_size)
            if step != 1:
                raise ValueError("Skip list slicing only supports a step of 1")
            result = bytearray()
            current = self._find_node(start)
            while current.forward[0] and start < stop:
                node_start = current.start
                chunk_start = max(start - node_start, 0)
                chunk_stop = min(stop - node_start, current.size)
                result.extend(current.chunk[chunk_start:chunk_stop])
                start += chunk_stop - chunk_start
                current = current.forward[0]
            return bytes(result)
        else:
            if index < 0:
                index += self.total_size
            if index < 0 or index >= self.total_size:
                raise IndexError("Skip list index out of range")
            current = self._find_node(index)
            offset = index - current.start
            return current.chunk[offset]

    def __setitem__(self, index, value):
        if isinstance(index, slice):
            start, stop, step = index.indices(self.total_size)
            if step != 1:
                raise ValueError("Skip list slicing only supports a step of 1")
            if stop - start != len(value):
                raise ValueError("Assigned value length does not match slice length")

            if isinstance(value, bytes):
                # Update the existing nodes within the slice range
                self._update_slice(start, stop, value)
            else:
                raise TypeError("Skip list slice assignment requires bytes")

        else:
            # Handle single byte assignment at the specified index
            if index < 0:
                index += self.total_size
            if index < 0 or index >= self.total_size:
                raise IndexError("Skip list index out of range")

            current, offset = self._find_node(index)
            node = current.forward[0]

            # Update the byte at the specified index in the bottom level node
            node.chunk = node.chunk[:offset] + bytes([value]) + node.chunk[offset + 1 :]

    def _update_slice(self, start, stop, value):
        if start >= stop:
            return

        current = self._find_node(start)
        index = start

        while current.forward[0] and index < stop:
            node_start = current.start
            node_stop = current.start + current.size

            if index < node_start:
                # Create a new node for the gap
                gap_size = min(node_start - index, stop - index)
                new_level = self._random_level()
                chunk = value[index - start : index - start + gap_size]
                gap_node = Node(start=index, chunk=chunk)
                self._insert_node(gap_node)
                index += gap_size

            if index >= node_start and index < node_stop:
                # Split the current node and insert a new node with the updated chunk
                chunk_start = index - node_start
                chunk_stop = min(node_stop - node_start, stop - index)

                # Create a new node for the updated chunk
                chunk = value[index - start : index - start + chunk_stop - chunk_start]
                updated_node = self._new_node(index, chunk)
                self._insert_node(updated_node)

                # Update the current node's chunk and size
                current.chunk = current.chunk[:chunk_start]
                current.size = chunk_start

                index += chunk_stop - chunk_start

            current = current.forward[0]

        if index < stop:
            # Create a new node for the remaining data
            remaining_size = stop - index
            chunk = value[index - start : index - start + remaining_size]
            remaining_node = self._new_node(index, chunk)
            self._insert_node(remaining_node)

    def _insert_node(self, new_node):
        update = [None] * (self.max_level + 1)
        current = self.header

        for i in range(self.level, -1, -1):
            while current.forward[i] and current.forward[i].start < new_node.start:
                current = current.forward[i]
            update[i] = current

        for i in range(new_node.level + 1):
            if i <= self.level:
                new_node.forward[i] = update[i].forward[i]
                update[i].forward[i] = new_node
            else:
                self.header.forward[i] = new_node

        self.level = max(self.level, new_node.level)
        self.total_size += new_node.size

    def __len__(self):
        return self.total_size

    def to_bytes(self):
        result = bytearray()
        current = self.header.forward[0]

        while current and current.chunk:
            result.extend(current.chunk)
            current = current.forward[0]

        return bytes(result)

    def display(self):
        print("Skip List:")
        for i in range(self.level, -1, -1):
            print(f"Level {i}: ", end="")
            current = self.header.forward[i]
            while current:
                if i == 0:
                    print(f"({current.chunk}, {current.start}) -> ", end="")
                else:
                    print(f"({current.start}) -> ", end="")
                current = current.forward[i]
            print("None")
        print()


s = SkipList()
s.display()

s.append(b"abc")
print(s.to_bytes())
s.display()

assert len(s) == 3
assert s[0] == b"a"[0]
assert s[1] == b"b"[0]

s.append(b"def")
s.append(b"hello")
s.append(b"world")
s.display()

assert len(s) == 16
print(s.to_bytes())
print(f"s[0] = {s[0]}")

assert s[0] == b"a"[0]
assert s[5] == b"f"[0]

assert s[1:4] == b"bcd"

s[1:4] = b"xyz"
print(f"s.to_bytes() after s[1:4] = b'xyz': {s.to_bytes()}")
print(f"len(s) = {len(s)}")
assert len(s) == 16

# TODO: fix _insert_node -> it's not supposed to do a middle insertion in our context, just overwriting
