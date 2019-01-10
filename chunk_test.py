from chunk import *
import unittest
import binascii


class TestChunkTypes(unittest.TestCase):
    def test_Chunk(self):
        test_raw_value = b"0123456789ABCDEF"
        test_human_value = "XXX"
        test_internal_value = "XXX"
        test_raw_length = len(test_raw_value)
        cobj = Chunk(name="test_chunk", raw_data=test_raw_value)

        cobj.display_string()

        cobj.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        self.assertEqual(test_raw_value, cobj.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, cobj.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, cobj.human2internal(test_human_value))
        self.assertEqual(test_human_value, cobj.internal2human(test_internal_value))

        cobj.validate_raw(test_raw_value)
        data_remain = cobj.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")
        #cobj.write_to_stream

    def test_ValueChunk_1(self):
        test_raw_value = "\x00\x63"
        test_human_value = "99"
        test_internal_value = 99
        test_raw_length = 2

        cobj = ValuePackChunk(name="test_chunk", raw_data=test_raw_value, fmt='>H')
        cobj.display_string()

        cobj.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        self.assertEqual(test_raw_value, cobj.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, cobj.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, cobj.human2internal(test_human_value))
        self.assertEqual(test_human_value, cobj.internal2human(test_internal_value))

        cobj.validate_raw(test_raw_value)
        data_remain = cobj.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_UShortChunk(self):
        test_raw_value = "\x12\x00"
        test_human_value = "18"
        test_internal_value = 18
        test_raw_length = 2

        cobj = UShortChunk(name="test_chunk", raw_data=test_raw_value)
        cobj.display_string()

        cobj.human_value = test_human_value  # test the setter
        cobj.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        self.assertEqual(test_raw_value, cobj.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, cobj.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, cobj.human2internal(test_human_value))
        self.assertEqual(test_human_value, cobj.internal2human(test_internal_value))

        cobj.validate_raw(test_raw_value)
        data_remain = cobj.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_CStringChunk(self):
        test_raw_value = b'ABCDEF\0'
        test_human_value = "ABCDEF"
        test_internal_value = b"ABCDEF"
        test_raw_length = 7

        cobj = CStringChunk(name="test_chunk", raw_data=test_raw_value)
        cobj.display_string()

        cobj.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        self.assertEqual(test_raw_value, cobj.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, cobj.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, cobj.human2internal(test_human_value))
        self.assertEqual(test_human_value, cobj.internal2human(test_internal_value))

        cobj.validate_raw(test_raw_value)
        data_remain = cobj.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_list_example_1(self):
        """ This is a fixed, 3 element long array, where each element is 4 bytes """
        test_data = b'\x00\x00\x00c\x00\x00\x00X\x00\x00\x00M'  # [99, 88, 77] (">L>L>L")
        cobj = HomogeneousList(name="test_chunk",
                               raw_data=test_data,
                               element_count=lambda x: 3,
                               element_type=(ULongChunk, {}))
        self.assertEqual(cobj.raw_length, 12)
        self.assertEqual(cobj.raw_value, '\x00\x00\x00c\x00\x00\x00X\x00\x00\x00M')
        #self.assertEqual(cobj.internal_value, 'ABCDEF')
        #self.assertEqual(cobj.human_value, 'ABCDEF')
        cobj.display_string()

    def test_list_example_2(self):
        """ This is a list object, where the length is specified in the preceding two bytes """
        class TESTLIST(HeterogeneousList):
            template = [(ValuePackChunk, {"name": "list_length",
                                          "fmt": "H",
                                          "length_from": lambda x: x.parent.list_data}),
                        (HomogeneousList, {"name": "list_data",
                                        "element_type": (BinaryDataChunk, {"length": 2}),
                                        "element_count": lambda x: x.parent.list_length.internal_value})]
        test_data = binascii.unhexlify("0400aaaabbbbccccF001")
        cobj = TESTLIST(name="test_chunk")
        cobj.read_from_stream(test_data)
        #cobj.raw_value = test_data
        self.assertEqual(cobj.raw_length, 10)
        cobj.display_string()

    def test_list_example_3(self):
        """ This is a list object, where the number if elements is specified in the preceding two bytes (rather than
        the length of the list in bytes) .... TODO """
        class TESTLIST(HeterogeneousList):
            template = [(ValuePackChunk, {"name": "list_length",
                                          "fmt": "H",
                                          "length_from": lambda x: x.parent.list_data}),
                        (HomogeneousList, {"name": "list_data",
                                        "element_type": (BinaryDataChunk, {"length": 2}),
                                        "element_count": lambda x: x.parent.list_length.internal_value})]
        test_data = binascii.unhexlify("0400aaaabbbbccccF001")
        cobj = TESTLIST(name="test_chunk")
        cobj.read_from_stream(test_data)
        #cobj.raw_value = test_data
        self.assertEqual(cobj.raw_length, 10)
        cobj.display_string()

    def test_list_example_4(self):
        """ This is a list object, where each element is two bytes and the end of the list is
        signified by a 0x0000 chunk """
        class TESTLIST(HeterogeneousList):
            template = [(ListChunk, {"name": "list_data",
                                     "element_type": (BinaryDataChunk, {"length": 2}),
                                     "length_from": lambda x: x.parent.list_length.value}),
                        (ValuePackChunk, {"name": "list_terminator",
                                          "fmt": "H",
                                          "default": 0x0000})]

        test_data = binascii.unhexlify("00aa11bb22cc33FFFF0000F001")
        cobj = TESTLIST(name="test_chunk", raw_data=test_data)
        self.assertEqual(cobj.internal2rawlength(), 9)
        cobj.display_string()

    def test_list_example_5(self):
        """ This is a list object, where each element is in TLV format (1 byte type, 1 byte len, and len bytes).
        The list is terminated by a TLV where the type byte is 0xFF. The length and value of the final element is not
        present in the message """
        class TESTTLV(HeterogeneousList):
            template = [(ValuePackChunk, {"name": "TLV_type", "fmt": "B"}),
                        (ValuePackChunk, {"name": "TLV_length", "fmt": "B",
                                          "conditional_fn": lambda x: x.parent.TLV_type.value != 0xff}),
                        (BinaryDataChunk, {"name": "TLV_data",
                                           "length_from": lambda x: x.parent.TLV_length.value,
                                           "conditional_fn": lambda x: x.parent.TLV_type.value != 0xff})]

        class TESTLIST(HeterogeneousList):
            template = [(ListChunk, {"name": "list_data",
                                     "element_type": (TESTTLV, {}) })]

        test_data = binascii.unhexlify("0002AAAA0104FFFFAAAAFFF001")  # three elements, the last element is the terminator
        cobj = TESTLIST(name="test_chunk", raw_data=test_data)
        self.assertEqual(cobj.internal2rawlength(), 11)
        cobj.display_string()

    def test_EnumChunk(self):
        TEST_ENUM = {0x0000: '(0x0000) Humpty Dumpty sat on a wall',
                     0x0001: '(0x0001) Humpty Dumpty had a great fall.',
                     0x0002: '(0x0002) All the king\'s horses and all the king\'s men',
                     0x0003: '(0x0003) Couldn\'t put Humpty together again.'}

        test_raw_value = b"\x00\x01"
        test_human_value = "(0x0001) Humpty Dumpty had a great fall."
        test_internal_value = 1
        test_raw_length = 2

        cobj = EnumPackChunk(name="test_chunk", enum=TEST_ENUM, raw_data=test_raw_value, fmt=">H")
        cobj.display_string()

        cobj.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        self.assertEqual(test_raw_value, cobj.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, cobj.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, cobj.human2internal(test_human_value))
        self.assertEqual(test_human_value, cobj.internal2human(test_internal_value))

        cobj.validate_raw(test_raw_value)
        data_remain = cobj.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_X3ByteIntChunk(self):
        test_raw_value = b"\x00\x00\x05"
        test_human_value = "5"
        test_internal_value = 5
        test_raw_length = 3

        cobj = X3ByteIntPackChunk(name="test_chunk", raw_data=test_raw_value)
        cobj.display_string()

        cobj.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        self.assertEqual(test_raw_value, cobj.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, cobj.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, cobj.human2internal(test_human_value))
        self.assertEqual(test_human_value, cobj.internal2human(test_internal_value))

        cobj.validate_raw(test_raw_value)
        data_remain = cobj.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_ASCIIEncodedDecimal(self):
        test_raw_value = b"\x32\x33"
        test_human_value = "23"
        test_internal_value = 23
        test_raw_length = 2

        cobj = ASCIIEncodedDecimal(name="test_chunk", raw_data=test_raw_value, raw_len=3)
        cobj.display_string()

        cobj.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        cobj.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, cobj.raw_value)  # test the property
        self.assertEqual(test_human_value, cobj.human_value)  # test the property
        self.assertEqual(test_internal_value, cobj.internal_value)  # test the property
        self.assertEqual(test_raw_length, cobj.raw_length)  # test the property

        self.assertEqual(test_raw_value, cobj.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, cobj.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, cobj.human2internal(test_human_value))
        self.assertEqual(test_human_value, cobj.internal2human(test_internal_value))

        cobj.validate_raw(test_raw_value)
        data_remain = cobj.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

if __name__ == '__main__':
    unittest.main()

