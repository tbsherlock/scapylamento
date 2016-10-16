from chunk import *
import unittest


class TestChunk(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_Chunk(self):
        """ Client hello"""
        test_data = "0123456789ABCDEF"
        cobj = Chunk(name="test_chunk", rawdata=test_data)
        """
        self.assertEqual(len(cobj), 16)  # check __len__ inbuilt
        cobj.human2internal("A quick brown fox")
        cobj.internal2human()
        cobj.raw2internal("Rapid package")
        cobj.internal2raw()
        cobj.validate_raw("Mysterious data-sets")
        cobj.raw_length()
        cobj.write_to_stream("abcdef")
        cobj.read_from_stream("ghijkl")
        cobj.display_string(indent="")
        cobj.copy()
        """

    def test_ValueChunk(self):
        test_data = '\x00c'  # 99
        cobj = ValuePackChunk(name="test_chunk", rawdata=test_data, fmt='>H')
        self.assertEqual(len(cobj), 2)  # check __len__ inbuilt
        self.assertEqual(cobj.internal2length(), 2)
        self.assertEqual(cobj.internal2raw(), '\x00c')
        #self.assertEqual(cobj.internal2human(),99)

        #cobj.write_to_stream("abcdef")
        #cobj.read_from_stream("ghijkl")
        #cobj.display_string(indent="")
        #cobj.human2internal("A quick brown fox")
        #cobj.raw2internal("Rapid package")
        #cobj.validate_raw("Mysterious data-sets")
        #cobj.copy()
        cobj.display_string()

    def test_CStringChunk(self):
        test_data = b'ABCDEF\0tricks'
        cobj = CStringChunk(name="test_chunk", rawdata=test_data)
        #self.assertEqual(len(cobj), 7)  # check __len__ inbuilt
        #self.assertEqual(cobj.raw_length(), 7)
        #self.assertEqual(cobj.internal2raw(), 'ABCDEF\0')
        #self.assertEqual(cobj.internal2human(), 'ABCDEF')
        cobj.display_string()

    def test_list_example_1(self):
        """ This is a fixed, 3 element long array, where each element is 4 bytes """
        test_data = '\x00\x00\x00c\x00\x00\x00X\x00\x00\x00M'  # [99, 88, 77] (">L>L>L")
        cobj = ListChunk(name="test_chunk", length_from = lambda x: 12,
                         rawdata=test_data, element_type=(ValuePackChunk, {"fmt": ">L"}))
        self.assertEqual(len(cobj), 12)  # check __len__ inbuilt
        self.assertEqual(cobj.internal2length(), 12)
        self.assertEqual(cobj.internal2raw(), '\x00\x00\x00c\x00\x00\x00X\x00\x00\x00M')
        cobj.internal2human()
        cobj.display_string()

    def test_list_example_2(self):
        """ This is a list object, where the length is specified in the preceding two bytes """
        class TESTLIST(TemplateChunk):
            template = [(ValuePackChunk, {"name": "list_length",
                                          "fmt": "H",
                                          "length_from": lambda x: x.parent.list_data}),
                        (ListChunk, {"name": "list_data",
                                     "element_type": (BinaryDataChunk, {"length": 2}),
                                     "length_from": lambda x: x.parent.list_length.value})]
        test_data = "0006aaaabbbbccccF001".decode('hex')
        cobj = TESTLIST(name="test_chunk", rawdata=test_data)
        self.assertEqual(len(cobj), 8)
        self.assertEqual(cobj.internal2length(), 8)
        cobj.display_string()

    def test_list_example_3(self):
        """ This is a list object, where the number if elements is specified in the preceding two bytes (rather than
        the length of the list in bytes) """
        class TESTLIST(TemplateChunk):
            template = [(ValuePackChunk, {"name": "list_length",
                                          "fmt": "H",
                                          "length_from": lambda x: x.parent.list_data}),
                        (ListChunk, {"name": "list_data",
                                     "element_type": (BinaryDataChunk, {"length": 2}),
                                     "length_from": lambda x: x.parent.list_length.value})]

        test_data = "0003aaaabbbbccccF001".decode('hex')
        cobj = TESTLIST(name="test_chunk", rawdata=test_data)
        self.assertEqual(len(cobj), 8)
        self.assertEqual(cobj.internal2length(), 8)
        cobj.display_string()

    def test_list_example_4(self):
        """ This is a list object, where each element is two bytes and the end of the list is
        signified by a 0x0000 chunk """
        class TESTLIST(TemplateChunk):
            template = [(ListChunk, {"name": "list_data",
                                     "element_type": (BinaryDataChunk, {"length": 2}),
                                     "length_from": lambda x: x.parent.list_length.value}),
                        (ValuePackChunk, {"name": "list_terminator",
                                          "fmt": "H",
                                          "default": 0x0000})]

        test_data = "00aa11bb22cc33FFFF0000F001".decode('hex')
        cobj = TESTLIST(name="test_chunk", rawdata=test_data)
        self.assertEqual(len(cobj), 9)
        self.assertEqual(cobj.internal2length(), 9)
        cobj.display_string()

    def test_list_example_5(self):
        """ This is a list object, where each element is in TLV format (1 byte type, 1 byte len, and len bytes).
        The list is terminated by a TLV where the type byte is 0xFF. The length and value of the final element is not
        present in the message """
        class TESTTLV(TemplateChunk):
            template = [(ValuePackChunk, {"name": "TLV_type", "fmt": "B"}),
                        (ValuePackChunk, {"name": "TLV_length", "fmt": "B",
                                          "conditional_fn": lambda x: x.parent.TLV_type.value != 0xff}),
                        (BinaryDataChunk, {"name": "TLV_data",
                                           "length_from": lambda x: x.parent.TLV_length.value,
                                           "conditional_fn": lambda x: x.parent.TLV_type.value != 0xff})]

        class TESTLIST(TemplateChunk):
            template = [(ListChunk, {"name": "list_data",
                                     "element_type": (TESTTLV, {}) })]

        test_data = "0002AAAA0104FFFFAAAAFFF001".decode('hex')  # three elements, the last element is the terminator
        cobj = TESTLIST(name="test_chunk", rawdata=test_data)
        self.assertEqual(len(cobj), 11)
        self.assertEqual(cobj.internal2length(), 11)
        cobj.display_string()

    def test_template_example_1(self):
        """ This is a template, where the first two bytes are a bitmap indicating which fields are present
        in the chunk """
        pass

    def test_LengthOfChunk(self):
        """ cke """
        pass


    def test_TemplateChunk(self):
        """ cke """

    def test_EnumChunk(self):
        TEST_ENUM = {0x0000: '(0x0000) Humpty Dumpty sat on a wall',
                     0x0001: '(0x0001) Humpty Dumpty had a great fall.',
                     0x0002: '(0x0002) All the king\'s horses and all the king\'s men',
                     0x0003: '(0x0003) Couldn\'t put Humpty together again.'}

        test_data = '0001'.decode('hex')
        cobj = EnumPackChunk(name="test_chunk", enum=TEST_ENUM, fmt=">H")
        self.assertEqual(len(cobj), 2)  # check __len__ inbuilt
        self.assertEqual(cobj.internal2length(), 2)
        cobj.display_string()

    def test_X3ByteIntChunk(self):
        test_data = '000001'.decode('hex')
        cobj = X3ByteIntPackChunk(name="test_chunk")
        self.assertEqual(len(cobj), 3)  # check __len__ inbuilt
        self.assertEqual(cobj.internal2length(), 3)
        cobj.display_string()

    def test_BinaryDataChunk(self):
        test_data = '000001ABCDEF'.decode('hex')
        cobj = BinaryDataChunk(name="test_chunk", rawdata=test_data, length=6)
        self.assertEqual(len(cobj), 6)  # check __len__ inbuilt
        self.assertEqual(cobj.internal2length(), 6)
        cobj.display_string()

if __name__ == '__main__':
    unittest.main()

