import binascii
import unittest

from dissectors import as2805


class TestChunk(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_LLVAR(self):
        test_raw_value = binascii.unhexlify(b"3034AABBAABB")
        test_human_value = "AABBAABB"
        test_internal_value = b"AABBAABB"
        test_raw_length = 6
        cobj = as2805.LLVARChunk(name="test_chunk", raw_data=test_raw_value)

        cobj.display_string()

        cobj.human_value = test_human_value  # test the setter
        self.assertEqual(cobj.raw_value, test_raw_value)  # test the property
        self.assertEqual(cobj.human_value, test_human_value)  # test the property
        self.assertEqual(cobj.internal_value, test_internal_value)  # test the property
        self.assertEqual(cobj.raw_length, test_raw_length)  # test the property

        cobj.raw_value = test_raw_value  # test the setter
        self.assertEqual(cobj.raw_value, test_raw_value)  # test the property
        self.assertEqual(cobj.human_value, test_human_value)  # test the property
        self.assertEqual(cobj.internal_value, test_internal_value)  # test the property
        self.assertEqual(cobj.raw_length, test_raw_length)  # test the property

        cobj.internal_value = test_internal_value  # test the setter
        self.assertEqual(cobj.raw_value, test_raw_value)  # test the property
        self.assertEqual(cobj.human_value, test_human_value)  # test the property
        self.assertEqual(cobj.internal_value, test_internal_value)  # test the property
        self.assertEqual(cobj.raw_length, test_raw_length)  # test the property

        self.assertEqual(cobj.internal2raw(test_internal_value), test_raw_value)
        self.assertEqual(cobj.internal2rawlength(test_internal_value), test_raw_length)
        self.assertEqual(cobj.human2internal(test_human_value), test_internal_value)
        self.assertEqual(cobj.internal2human(test_internal_value), test_human_value)

        cobj.validate_raw(test_raw_value)
        data_remain = cobj.read_from_stream(test_raw_value + b"11223344")
        self.assertEqual(data_remain, b"11223344")

    def test_primary_bitmap(self):
        test_data = binascii.unhexlify("8020000000C10002")
        cobj = as2805.PrimaryBitmap(name="test_primary_bitmap", raw_data=test_data)
        self.assertEqual(test_data, cobj.raw_value)

        """ Check some fields which are set """
        self.assertEqual(cobj.get_field("Extended bitmap"), True)
        self.assertEqual(cobj.get_field(1), True)
        self.assertEqual(cobj.get_field("Systems trace audit number"), True)
        self.assertEqual(cobj.get_field(11), True)
        self.assertEqual(cobj.get_field("Card acceptor terminal identification"), True)
        self.assertEqual(cobj.get_field(41), True)
        self.assertEqual(cobj.get_field("Additional data - Private"), True)
        self.assertEqual(cobj.get_field(48), True)

        """ Check some fields which are not set """
        self.assertEqual(cobj.get_field("Conversion rate, Cardholder"), False)
        self.assertEqual(cobj.get_field(10), False)
        self.assertEqual(cobj.get_field(12), False)
        self.assertEqual(cobj.get_field(40), False)

        """ Check a whole byte """
        self.assertEqual(cobj.get_field(9), False)
        self.assertEqual(cobj.get_field(10), False)
        self.assertEqual(cobj.get_field(11), True)
        self.assertEqual(cobj.get_field(12), False)
        self.assertEqual(cobj.get_field(13), False)
        self.assertEqual(cobj.get_field(14), False)
        self.assertEqual(cobj.get_field(15), False)
        self.assertEqual(cobj.get_field(16), False)

        """ Some error states"""
        with self.assertRaises(Exception):
            cobj.get_field(65)

        with self.assertRaises(Exception):
            cobj.get_field(-1)

        with self.assertRaises(Exception):
            cobj.get_field("NOT A REAL FIELD")

        with self.assertRaises(Exception):
            cobj.get_field(None)

        """ set and unset """
        cobj.set_field("Conversion rate, Cardholder", True)
        self.assertEqual(cobj.get_field("Conversion rate, Cardholder"), True)

        cobj.set_field("Conversion rate, Cardholder", False)
        self.assertEqual(cobj.get_field("Conversion rate, Cardholder"), False)

        cobj.display_string(indent="")

    def test_extended_bitmap(self):
        test_data = binascii.unhexlify("0400000000000000")
        cobj = as2805.ExtendedBitmap(name="test_extended_bitmap", raw_data=test_data)
        self.assertEqual(test_data, cobj.raw_value)

        """ Check some fields which are set """
        self.assertEqual(cobj.get_field("Network management information"), True)
        self.assertEqual(cobj.get_field(70), True)

        """ Check some fields which are not set """
        self.assertEqual(cobj.get_field("Settlement institution country code"), False)
        self.assertEqual(cobj.get_field(69), False)

        """ Check a whole byte """
        self.assertEqual(cobj.get_field(73), False)
        self.assertEqual(cobj.get_field(74), False)
        self.assertEqual(cobj.get_field(75), False)
        self.assertEqual(cobj.get_field(76), False)
        self.assertEqual(cobj.get_field(77), False)
        self.assertEqual(cobj.get_field(78), False)
        self.assertEqual(cobj.get_field(79), False)
        self.assertEqual(cobj.get_field(80), False)

        """ Some error states"""
        with self.assertRaises(Exception):
            cobj.get_field(60)

        with self.assertRaises(Exception):
            cobj.get_field(130)

        with self.assertRaises(Exception):
            cobj.get_field("NOT A REAL FIELD")

        with self.assertRaises(Exception):
            cobj.get_field(None)

        """ set and unset """
        cobj.set_field("Extended payment code", True)
        self.assertEqual(cobj.get_field("Extended payment code"), True)

        cobj.set_field("Extended payment code", False)
        self.assertEqual(cobj.get_field("Extended payment code"), False)

        cobj.display_string(indent="")

    def test_b(self):
        # request
        sample_message = binascii.unhexlify(
            "98208020000000C1000204000000000000000000013132333435363738333131"
            "303030303631323334353637373736DFFDA39886F5EE5A799E908318F29B5A08"
            "39FDEFFFEDEE1123499495E9C9060F2618CAF5856824EF03F71CC8C331B1F6E2"
            "B3ECBEE2ACE326CCEA260531F88C678470E6398412D469690414F0825DAA0D43"
            "8DF7475AD17D7259A9F1C5DF5BC45818332B5425AF1B6C0EC8A291BDD85FDE2F"
            "0F2C39883C29BBCC7AE2F5BAEA716840D500197C824401075706BBEC006FE293"
            "F5F24F25851E2B52EB8299F3D22F0F65976C71E259BC37D33067E0ADB1AD2452"
            "34AA1CB74C19575E026D1FC5B7937E1080D3BD94DA9ED48B1EC5327503919C3B"
            "5BC105284B0EFE52D54F6CF5D3163A71C5D33404565763168A2694FFFA6E5D67"
            "9C04BC32A2559C472CB13B4734AB890000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000100015C72632C1FAEABAA4645ACC8CE237EE951"
            "D016C52FA2FF73588D089264279716B240EF139C1173D197DB8026F7D9600356"
            "8A2D05D3B20E2D2D7377EB73123C711D72C8A6A6FFE7B24D7D7807B6FA4FDCD6"
            "A75A52D1FCC4301B4C2039729ACAA652B5F4643AAB33400719D5D67A0738138D"
            "8496C3F773DE2C801FDECB0E18064D306BCE706C107CD0603960EDCDAAF92F43"
            "2B8EB1978AE8136F5E2E7802BA38DDE97EAF05EC11F67A6646A61BCD23AF6DB7"
            "46DFA81D54103CCFF8832B588E8099159A38729D511D5F2A97CEBFFB2FB02CAC"
            "AAE7012C64FD42229075164941E3FE15FE3EE0E9FCC3897B308C111E9F5F3AFE"
            "2B584F244ECC0950043F6F20D0BE3B1122334455667788303031330191")
        b = as2805.AS2805_message()
        b.read_from_stream(sample_message)
        print("b=", b)
        print("B=", b.display_string())
        print("braw=", b.raw_value)
        self.assertEqual(sample_message, b.raw_value)

        newb = as2805.AS2805_message()
        newb.set_type(b"\x98\x20")
        newb.set_field("Systems trace audit number", b"\x00\x00\x01")
        newb.set_field("Card acceptor terminal identification", binascii.unhexlify("3132333435363738"))
        newb.set_field("Card acceptor identification code", binascii.unhexlify("333131303030303631323334353637"))
        newb.set_field("Additional data - Private", binascii.unhexlify("373736DFFDA39886F5EE5A799E908318F29B5A08"
            "39FDEFFFEDEE1123499495E9C9060F2618CAF5856824EF03F71CC8C331B1F6E2"
            "B3ECBEE2ACE326CCEA260531F88C678470E6398412D469690414F0825DAA0D43"
            "8DF7475AD17D7259A9F1C5DF5BC45818332B5425AF1B6C0EC8A291BDD85FDE2F"
            "0F2C39883C29BBCC7AE2F5BAEA716840D500197C824401075706BBEC006FE293"
            "F5F24F25851E2B52EB8299F3D22F0F65976C71E259BC37D33067E0ADB1AD2452"
            "34AA1CB74C19575E026D1FC5B7937E1080D3BD94DA9ED48B1EC5327503919C3B"
            "5BC105284B0EFE52D54F6CF5D3163A71C5D33404565763168A2694FFFA6E5D67"
            "9C04BC32A2559C472CB13B4734AB890000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000100015C72632C1FAEABAA4645ACC8CE237EE951"
            "D016C52FA2FF73588D089264279716B240EF139C1173D197DB8026F7D9600356"
            "8A2D05D3B20E2D2D7377EB73123C711D72C8A6A6FFE7B24D7D7807B6FA4FDCD6"
            "A75A52D1FCC4301B4C2039729ACAA652B5F4643AAB33400719D5D67A0738138D"
            "8496C3F773DE2C801FDECB0E18064D306BCE706C107CD0603960EDCDAAF92F43"
            "2B8EB1978AE8136F5E2E7802BA38DDE97EAF05EC11F67A6646A61BCD23AF6DB7"
            "46DFA81D54103CCFF8832B588E8099159A38729D511D5F2A97CEBFFB2FB02CAC"
            "AAE7012C64FD42229075164941E3FE15FE3EE0E9FCC3897B308C111E9F5F3AFE"
            "2B584F244ECC0950043F6F20D0BE3B1122334455667788"))
        newb.set_field("63 - Reserved private", b"\x33")
        newb.set_field("Network management information", b"\01\x91")
        print("b2=", newb)
        print("B2=", newb.display_string())
        print("braw1=", binascii.hexlify(b.raw_value))
        print("braw2=", binascii.hexlify(newb.raw_value))
        #self.assertEqual(sample_message, newb.raw_value)

    def test_c(self):
        # request response
        sample_message = binascii.unhexlify(
            "98308020000000C1000204000000000000000000013132333435363738333131"
            "303030303631323334353637373736DFFDA39886F5EE5A799E908318F29B5A08"
            "39FDEFFFEDEE1123499495E9C9060F2618CAF5856824EF03F71CC8C331B1F6E2"
            "B3ECBEE2ACE326CCEA260531F88C678470E6398412D469690414F0825DAA0D43"
            "8DF7475AD17D7259A9F1C5DF5BC45818332B5425AF1B6C0EC8A291BDD85FDE2F"
            "0F2C39883C29BBCC7AE2F5BAEA716840D500197C824401075706BBEC006FE293"
            "F5F24F25851E2B52EB8299F3D22F0F65976C71E259BC37D33067E0ADB1AD2452"
            "34AA1CB74C19575E026D1FC5B7937E1080D3BD94DA9ED48B1EC5327503919C3B"
            "5BC105284B0EFE52D54F6CF5D3163A71C5D33404565763168A2694FFFA6E5D67"
            "9C04BC32A2559C472CB13B4734AB890000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000100015C72632C1FAEABAA4645ACC8CE237EE951"
            "D016C52FA2FF73588D089264279716B240EF139C1173D197DB8026F7D9600356"
            "8A2D05D3B20E2D2D7377EB73123C711D72C8A6A6FFE7B24D7D7807B6FA4FDCD6"
            "A75A52D1FCC4301B4C2039729ACAA652B5F4643AAB33400719D5D67A0738138D"
            "8496C3F773DE2C801FDECB0E18064D306BCE706C107CD0603960EDCDAAF92F43"
            "2B8EB1978AE8136F5E2E7802BA38DDE97EAF05EC11F67A6646A61BCD23AF6DB7"
            "46DFA81D54103CCFF8832B588E8099159A38729D511D5F2A97CEBFFB2FB02CAC"
            "AAE7012C64FD42229075164941E3FE15FE3EE0E9FCC3897B308C111E9F5F3AFE"
            "2B584F244ECC0950043F6F20D0BE3B1122334455667788303031330191")
        c = as2805.AS2805_message()
        c.read_from_stream(sample_message)
        print("c=", c)
        print("C=", c.display_string())
        print("craw=", c.raw_value)
        self.assertEqual(sample_message, c.raw_value)

    def test_d(self):
        sample_message = binascii.unhexlify(
            "98208020000000C100020400000000000000000002313233343536373833313130303030363132333435363735323098A1C8592497A8B16849B1A95F3F0FCA4FCD61CC515BED423D35C21425DEEBAB0D9736FEAC884812835E91B6038EE0A1724A3899D705A9AC5C53BFD7200906EA30F70322AA4AFAA92BC8332ADDAFF2B6C69850C5363A82B8D824680B90DC98CA07BECA334CB18227CC826B25937412D8DDEF795D6DE4D32CAE4259E397B816528EE54C2C67C3A8B8ECD1806BF2F87FA5FED2D56B21303903C60C69D78E99B3CA43C77212F3A92C3F0E283F47D72EB44714569A03473E1FB3C353294FFDECDC3B54E4DDB125E8954A05B0B687DEC5DE1DECBC03788756DAF598AF3C212404BC6A6926FBD3E6D0BC8EE9BEA8FF68B2A2AD2E3A2E66F3ED20BE3D007093E266B5B4B03D8F933ECAD5AF954E5DB3BAA88041FBA6B8B0B0E44AF7CB099321E099D794388F849A831666C25F2622E9F67D78A87304498FBC5571452E8859C22D506ABA060D2FE419A9871C3CDD27A87C2B19311673771C4C19F0F04772D2C6961A42A12BA5A6137DA331FFF23C91F432BC6CE54879CA24712F2EC1491F550E48F9914CF617664ED993B657FC47030F45460AC189A2CDA3F3ACE8BB554FC1D92D548EE6CA8CAC8D70D67A1B373F1639FFACDA0D60FCEA419B8C0CA932F5560D61C8FED660D97C1C9955DFCA71EAA35E7E885009B380FC6761786BF0B828CB6A9DADE50CA2948E4A967501F9E9A92BE53DAF4847A56393842744A653B34A3284A07F75C91122334455667788303031330192")
        d = as2805.AS2805_message()
        d.read_from_stream(sample_message)
        print("d=", d)
        print("D=", d.display_string())
        print("draw=", d.raw_value)
        self.assertEqual(sample_message, d.raw_value)

    def test_e(self):
        sample_message = binascii.unhexlify(
            "98308020000002C1000004000000000000000000023030313233343536373833313130303030363132333435363730333848C87751C3F8D9AB098AF21B79CB9BE2D1458A402422B4B3C860C4FB9D1A690F1100056022000192")
        e = as2805.AS2805_message()
        e.read_from_stream(sample_message)
        print("e=", e)
        print("E=", e.display_string())
        print("eraw=", binascii.hexlify(e.raw_value))
        print("einn=", binascii.hexlify(sample_message))

        self.assertEqual(sample_message, e.raw_value)

        rdata = e.raw_value
        chunks = iter(lambda: rdata.read(32), b'')
        hexlines = map(binascii.hexlify, chunks)
        print(hexlines)