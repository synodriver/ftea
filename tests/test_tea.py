"""
Copyright (c) 2008-2021 synodriver <synodriver@gmail.com>
"""
from random import randint
from unittest import TestCase
import time

import pytea
import ftea


class TestTea(TestCase):
    def setUp(self) -> None:
        self.old = pytea.TEA(bytes(16))
        self.new = ftea.TEA(bytes(16))

    def test_decrypt(self):
        for i in range(10000):
            rand_data = bytes(randint(0, 255) for _ in range(randint(1, 1000)))
            encoded = self.old.encrypt(rand_data)
            self.assertEqual(self.new.decrypt_qq(encoded), rand_data)

    def test_speed(self):
        data = bytes(1 for _ in range(10000))
        start = time.time()
        for i in range(1000):
            self.old.encrypt(data)
        print(f"old spend {time.time() - start}")
        start = time.time()
        for i in range(1000):
            self.new.encrypt_qq(data)
        print(f"new spend {time.time() - start}")


if __name__ == "__main__":
    import unittest

    unittest.main()
