from chunk import *
import unittest
import binascii


class TestChunkTypes(unittest.TestCase):
    def test_OctetStringChunk(self):
        test_raw_value = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        test_human_value = "0123456789abcdef"
        test_internal_value = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        test_raw_length = 8

        test_object = OctetStringChunk(name="test_chunk", raw_value=test_raw_value)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_ValueChunk_1(self):
        test_raw_value = b"\x00\x63"
        test_human_value = "99"
        test_internal_value = 99
        test_raw_length = 2

        test_object = ValuePackChunk(name="test_chunk", raw_value=test_raw_value, fmt='>H')
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_ValueChunk_2(self):
        test_raw_value = b"\x99\x99\x66\x66\x00\x0F\xF0\x00"
        test_human_value = "-7378753926196105216"
        test_internal_value = -7378753926196105216
        test_raw_length = 8

        test_object = ValuePackChunk(name="test_chunk", raw_value=test_raw_value, fmt='>q')
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_ShortChunk(self):
        test_raw_value = b"\x96\x96"
        test_human_value = "-26986"
        test_internal_value = -26986
        test_raw_length = 2

        test_object = ShortChunk(name="test_chunk", raw_value=test_raw_value)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_UShortChunk(self):
        test_raw_value = b"\x96\x96"
        test_human_value = "38550"
        test_internal_value = 38550
        test_raw_length = 2

        test_object = UShortChunk(name="test_chunk", raw_value=test_raw_value)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_LongChunk(self):
        test_raw_value = b"\x96\x96\x96\x96"
        test_human_value = "-1768515946"
        test_internal_value = -1768515946
        test_raw_length = 4

        test_object = LongChunk(name="test_chunk", raw_value=test_raw_value)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_ULongChunk(self):
        test_raw_value = b"\x96\x96\x96\x96"
        test_human_value = "2526451350"
        test_internal_value = 2526451350
        test_raw_length = 4

        test_object = ULongChunk(name="test_chunk", raw_value=test_raw_value)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_FloatChunk(self):
        test_raw_value = b"\x00\x00\x80\x3f"
        test_human_value = "1.0"
        test_internal_value = 1.0
        test_raw_length = 4

        test_object = FloatChunk(name="test_chunk", raw_value=test_raw_value)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_CStringChunk(self):
        test_raw_value = b'ABCDEF\x00'
        test_human_value = "ABCDEF"
        test_internal_value = b"ABCDEF"
        test_raw_length = 7

        test_object = CStringChunk(name="test_chunk", raw_value=test_raw_value)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_EnumDataChunk(self):
        enum = {
            b"aaaaaaaa": "test_value_a",
            b"bbbbbbbb": "test_value_b",
            b"bbbbbbbb": "test_value_c",
        }
        test_raw_value = b'bbbbbbbb'
        test_human_value = "test_value_b"
        test_internal_value = b"bbbbbbbb"
        test_raw_length = 4

        test_object = EnumDataChunk(name="test_chunk", raw_value=test_raw_value)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    '''
    def test_list_example_1(self):
        """ This is a fixed, 3 element long array, where each element is 4 bytes """
        test_data = b'\x00\x00\x00\x99\x00\x00\x00\x88\x00\x00\x00\x77'  # [99, 88, 77] (">L>L>L")
        test_object = HomogeneousList(name="test_chunk",
                                    raw_value=test_data,
                                    element_count=lambda x: 3,
                                    element_type=(ULongChunk, {}))
        self.assertEqual(test_object.raw_length, 12)
        self.assertEqual(test_object.raw_value, '\x00\x00\x00c\x00\x00\x00X\x00\x00\x00M')
        #self.assertEqual(test_object.internal_value, 'ABCDEF')
        #self.assertEqual(test_object.human_value, 'ABCDEF')
        test_object.display_string()

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
        test_object = TESTLIST(name="test_chunk")
        test_object.read_from_stream(test_data)
        #test_object.raw_value = test_data
        self.assertEqual(test_object.raw_length, 10)
        test_object.display_string()

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
        test_object = TESTLIST(name="test_chunk")
        test_object.read_from_stream(test_data)
        #test_object.raw_value = test_data
        self.assertEqual(test_object.raw_length, 10)
        test_object.display_string()

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
        test_object = TESTLIST(name="test_chunk", raw_value=test_data)
        self.assertEqual(test_object.internal2rawlength(), 9)
        test_object.display_string()

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
        test_object = TESTLIST(name="test_chunk", raw_value=test_data)
        self.assertEqual(test_object.internal2rawlength(), 11)
        test_object.display_string()
    '''


    def test_EnumChunk(self):
        TEST_ENUM = {0x0000: '(0x0000) Humpty Dumpty sat on a wall',
                     0x0001: '(0x0001) Humpty Dumpty had a great fall.',
                     0x0002: '(0x0002) All the king\'s horses and all the king\'s men',
                     0x0003: '(0x0003) Couldn\'t put Humpty together again.'}

        test_raw_value = b"\x00\x01"
        test_human_value = "(0x0001) Humpty Dumpty had a great fall."
        test_internal_value = 1
        test_raw_length = 2

        test_object = EnumPackChunk(name="test_chunk", enum=TEST_ENUM, raw_value=test_raw_value, fmt=">H")
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_X3ByteIntChunk(self):
        test_raw_value = b"\x00\x00\x05"
        test_human_value = "5"
        test_internal_value = 5
        test_raw_length = 3

        test_object = X3ByteIntPackChunk(name="test_chunk", raw_value=test_raw_value)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_ASCIIEncodedDecimal(self):
        test_raw_value = b"\x32\x33"
        test_human_value = "23"
        test_internal_value = 23
        test_raw_length = 2

        test_object = ASCIIEncodedDecimal(name="test_chunk", raw_value=test_raw_value, raw_len=3)
        test_object.display_string()

        test_object.human_value = test_human_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.raw_value = test_raw_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        test_object.internal_value = test_internal_value  # test the setter
        self.assertEqual(test_raw_value, test_object.raw_value)  # test the property
        self.assertEqual(test_human_value, test_object.human_value)  # test the property
        self.assertEqual(test_internal_value, test_object.internal_value)  # test the property
        self.assertEqual(test_raw_length, test_object.raw_length)  # test the property

        self.assertEqual(test_raw_value, test_object.internal2raw(test_internal_value))
        self.assertEqual(test_raw_length, test_object.internal2rawlength(test_internal_value))
        self.assertEqual(test_internal_value, test_object.human2internal(test_human_value))
        self.assertEqual(test_human_value, test_object.internal2human(test_internal_value))

        test_object.validate_raw(test_raw_value)
        test_obj, data_remain = test_object.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")


if __name__ == '__main__':
    unittest.main()

