"""
Copyright (c) 2008-2021 synodriver <synodriver@gmail.com>
"""
import sys

sys.path.append(".")

import time
from random import randint
from unittest import TestCase

import pytea
import rtea

import ftea


class TestTea(TestCase):
    def setUp(self) -> None:
        self.old = pytea.TEA(b"1234567812345678")
        self.new = ftea.TEA(b"1234567812345678")

    def test_encrypt_rs(self):
        for i in range(10000):
            rand_data = bytes(randint(0, 255) for _ in range(randint(1, 1000)))
            encoded = self.new.encrypt_qq(rand_data)
            self.assertEqual(
                rtea.qqtea_decrypt(encoded, b"1234567812345678"), rand_data
            )

    def test_decrypt_rs(self):
        for i in range(10000):
            rand_data = bytes(randint(0, 255) for _ in range(randint(1, 1000)))
            encoded = rtea.qqtea_encrypt(rand_data, b"1234567812345678")
            self.assertEqual(self.new.decrypt_qq(encoded), rand_data)

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
        print(f"ftea spend {time.time() - start}")

        start = time.time()
        for i in range(1000):
            rtea.qqtea_encrypt(data, b"1234567812345678")
        print(f"rtea spend {time.time() - start}")


if __name__ == "__main__":
    import unittest

    unittest.main()
