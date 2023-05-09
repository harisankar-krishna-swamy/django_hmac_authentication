from unittest import TestCase

from ddt import data, ddt, unpack

from django_hmac_authentication.padding import pad, unpad


@ddt
class TestPadding(TestCase):

    test_data = (
        (0,),
        (8,),
        (16,),
        (32,),
        (64,),
        (128,),
    )

    @data(*test_data)
    @unpack
    def test_padding(self, block_size=16):
        data = b'test_data'
        block_size = 8
        padded = pad(data, block_size)
        unpadded = unpad(padded)
        self.assertEqual(data, unpadded, f'Padding error with block_size {block_size}')
