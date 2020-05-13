#!/usr/bin/python3

import unittest
from kakaodecrypt import KakaoDecrypt

class KakaoDecryptTest(unittest.TestCase):
  def testGenSalt(self):
    zero = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    self.assertEqual(KakaoDecrypt.genSalt(-1, 5), zero)
    self.assertEqual(KakaoDecrypt.genSalt(0, 5), zero)
    self.assertEqual(KakaoDecrypt.genSalt(1234, 0), b"1234\0\0\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 1), b"1234\0\0\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 2), b"121234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 3), b"241234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 4), b"181234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 5), b"301234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 6), b"361234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 7), b"121234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 8), b"481234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 9), b"71234\0\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 10), b"351234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 11), b"401234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 12), b"171234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 13), b"231234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 14), b"291234\0\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 15), b"isabel1234\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 16), b"kale1234\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 17), b"sulli1234\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 18), b"van1234\0\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 19), b"merry1234\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 20), b"kyle1234\0\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(1234, 21), b"james1234\0\0\0\0\0\0\0")
    self.assertEqual(KakaoDecrypt.genSalt(216658451, 17), b"sulli216658451\0\0")
    self.assertRaises(ValueError, KakaoDecrypt.genSalt, 1234, 42)

  def testDecryptMessage(self):
    self.assertEqual(KakaoDecrypt.decrypt(216658451, 17, 'UHVw8VBhUhdbIFTlvdBXdA=='), 'Hey friends!')
    self.assertEqual(KakaoDecrypt.decrypt(240440409, 22, 'pBO6rG5DQmOOfRwyoV6nqw=='), 'ㄱㅇㄷ')
    self.assertEqual(KakaoDecrypt.decrypt(195847548, 24, 'IICZJO/83CXZWZhNmiWmHg=='), "It's ok")
    self.assertEqual(KakaoDecrypt.decrypt(1234, 1, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    self.assertEqual(KakaoDecrypt.decrypt(283456151, 26, 'gYKexDBLvO7OwDqjD58LlQ=='), 'i have lasers')
    self.assertEqual(KakaoDecrypt.decrypt(77289285161409090,26,"6ooWLeWv/zcVSNsm8X44SOqc/Yg9u2wYe9HolLxmLOw="), '끙끙거리면서')
    self.assertEqual(KakaoDecrypt.decrypt(749346, 27, 'rB5tNoqR5OWeuvC4OC3shQ=='), 'ㅋㅋ')
    self.assertEqual(KakaoDecrypt.decrypt(16996603, 28, 'Q8VGaqRdqzOor5W6xn27jZJSEx1I8Z4fhUP4M8eguyc='), 'ㅋㅋㅋㅋㅋㅋㅋㅋ')
    self.assertEqual(KakaoDecrypt.decrypt(3569453, 29, '8lcerV0hiB3p/oo44pgBZQ=='), 'ㅇㅋ')


if __name__ == '__main__':
  unittest.main()
