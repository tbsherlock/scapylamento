from ssltls import TLSPacket
import unittest


class TestSSLTLS(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_packet_1(self):
        """ Client hello"""
        testpacket_raw = "16030100be010000ba0303e9ce4eb87da08dd32cac29655ee330b058eda2e9f4a67c6483ee7daaab7c3c79000022c02bc02fc02cc030cca9cca8cc14cc13c009c013c00ac014009c009d002f0035000a0100006fff0100010000000013001100000e7777772e676f6f676c652e636f6d0017000000230000000d0012001006010603050105030401040302010203000500050100000000001200000010000e000c02683208687474702f312e3175500000000b00020100000a00080006001d00170018".decode('hex')
        testpacket = TLSPacket(rawdata=testpacket_raw)
        print("client hello:\n %s" % (testpacket.display_string()))

    def test_packet_2(self):
        """ server hello"""
        testpacket_raw = "1603030200020001fc030357afe9ef9d37e0728c9272ff292d749384745405736f4afeec821b3705e4af0b00c02f0001d4ff01000100000000000017000000230000001201ac01aa007700a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc1000000156616d4e030000040300483046022100dfc609ea6fbe6cab506e3961108b011e758b86d4184db92ee535a18009f2e95e022100de83ce20dad6acb9a48d9058d984a3fdb84637cf824c580159ea9b6f80b42f7b012f00ac3b9aed7fa9674757159e6d7d575672f9d98100941e9bdeffeca1313b75782d00000156616d4ced0000040101001407c5a722bb8d3ef2aa9855795dcba0a48dd2312ad4aa60c1cf779a2de9f733fc475f72eb6e89a73b011f01be8fbf00076e2eea5f39f169de9aa1a0b77b242789068703cb4e66c92a4d05f4d47fcdade68e5a99a6f288819b4dfedd929d191ac76f75e4212f67969a6c8f4f279a14cf60983850824d0f33e643ea5bca006b6c566240123f8557779404a8bb5d6272bf46afee7ee5183846b4be43fd3506d7ab99b9395d8a881ea65628891066129e75f18b80f9f742a2456b8d2ce8ec2608a86aed1fb01137e04ae41b8753bcd680334615e544c809adc861424e6ca50be0f37a046445f70c2ba3da11b55965fd144c27ef58f1bbfcb45fb63c444fe6a6ff5300100005000302683275500000000b00020100".decode('hex')
        testpacket = TLSPacket(rawdata=testpacket_raw)
        print("server hello:\n %s" % (testpacket.display_string()))

    def test_packet_3(self):
        """ Certificate"""
        testpacket_raw = "1603030c090b000c05000c020004843082048030820368a003020102020869b7509b34855884300d06092a864886f70d01010b05003049310b300906035504061302555331133011060355040a130a476f6f676c6520496e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f72697479204732301e170d3136303830363138323434315a170d3136313032373137353830305a3068310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f676c6520496e633117301506035504030c0e7777772e676f6f676c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a028201010096102c3b234aac2ad31a01ae9cd27feb8b0063c3aba6b6cee118a1b675f2fa296a34e9425cfebc41ed30353fd5e065074c7df06701e1d3adc2ad466391e02134200235d3e4530216da77333d669fbb5805fd155217e9076c0aabc3fb5a14a9a46c03383f98c9fa88523556733880b11cf50966ff55aefffbc3fff496a14551f69950b9e1501c72ba6602e043067e17ec3e31e9cbbba6abff393ffb563f9ea466b0091fbca133fa214c87480c5dbacbde220356e152a91fb2af6d011a179fe8864e2bb96ce1c510aba9ef09b856b5fd51fbbc738512839307a3b0879600c85e75efac86b74bd5dd0cd2ff7b1edcd4bb0f0b121e0a72162a02801c9affbfc6bde50203010001a382014b30820147301d0603551d250416301406082b0601050507030106082b0601050507030230190603551d1104123010820e7777772e676f6f676c652e636f6d306806082b06010505070101045c305a302b06082b06010505073002861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e636f6d2f6f637370301d0603551d0e04160414974b6554581037b43aac234df1e5d1824c0f9eff300c0603551d130101ff04023000301f0603551d230418301680144add06161bbcf668b576f581b6bb621aba5a812f30210603551d20041a3018300c060a2b06010401d6790205013008060667810c01020230300603551d1f042930273025a023a021861f687474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e63726c300d06092a864886f70d01010b0500038201010015645a24cd0d018d5fe9dbf810eb21052f35bb223081210b6d7385cf5d626a83d5c7c407de78eb075dca95e9b71d8a23d0900c2b2deffd101f20c20569be5d9372aa2358b794e6ef20b326ba024d9e3cb94c6b7df14d99b54c4de6ebdbed929b86ab5cc75b613eff586498678eabb48762fd96ce2af7194d6067b693294c06b245ec1326cca7ca6c254df698bb166d6037aa3001d57bce724480dea2f87df811707624eb42175d2d34d79b1d3277d0f4567a951fb5aeddf6c182bec138d3fd10a4a9d571dcbb0f05c76fc88610ffab040ab4751704f878f510a1d486351929b07001c8a4c54f8505f3aec473fd3e82c30034aa8dcf968ebdc352cfd0ad13cb4b0003f4308203f0308202d8a0030201020203023a92300d06092a864886f70d01010b05003042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c204341301e170d3135303430313030303030305a170d3137313233313233353935395a3049310b300906035504061302555331133011060355040a130a476f6f676c6520496e63312530230603550403131c476f6f676c6520496e7465726e657420417574686f7269747920473230820122300d06092a864886f70d01010105000382010f003082010a02820101009c2a04775cd850913a06a382e0d85048bc893ff119701a88467ee08fc5f189ce21ee5afe610db7324489a0740b534f55a4ce826295eeeb595fc6e1058012c45e943fbc5b4838f453f724e6fb91e915c4cff4530df44afc9f54de7dbea06b6f87c0d0501f28300340da0873516c7fff3a3ca737068ebd4b1104eb7d24dee6f9fc3171fb94d560f32e4aaf42d2cbeac46a1ab2cc53dd154b8b1fc819611fcd9da83e632b8435696584c819c54622f85395bee3804a10c62aecba972011c739991004a0f0617a95258c4e5275e2b6ed08ca14fcce226ab34ecf46039797037ec0b1de7baf4533cfba3e71b7def42525c20d35899d9dfb0e1179891e37c5af8e72690203010001a381e73081e4301f0603551d23041830168014c07a98688d89fbab05640c117daa7d65b8cacc4e301d0603551d0e041604144add06161bbcf668b576f581b6bb621aba5a812f300e0603551d0f0101ff040403020106302e06082b0601050507010104223020301e06082b060105050730018612687474703a2f2f672e73796d63642e636f6d30120603551d130101ff040830060101ff02010030350603551d1f042e302c302aa028a0268624687474703a2f2f672e73796d63622e636f6d2f63726c732f6774676c6f62616c2e63726c30170603551d200410300e300c060a2b06010401d679020501300d06092a864886f70d01010b05000382010100084e04a7807f1016435e02add74280f4b08ed2aeb3eb117d9084187de79015fb497fa8990591bb7ac9d63c3718099ab6c7922007353309e42863720db4e0329c8798c41b768967c15058b013aa131a1b32a5beea11954c486349e9995d2037ccfe2a695116954ba9de4982c01070f42cf3ecbc2424d04eaca5d95e1e6d92c1a7ac483581f9e5e49c6569cd87a441503f2e57a5915112580e8c09a1ac7aa412a527f39a10977d550306f766585f5f64e1ab5d6da5394875984c295a3a8dd32bca9c5504bff4e614d580ac26ed1789a6936c5ca4ccb8f0668e64e37d9ae200b349c7e40aaadd5b83c77090464ebed0db59966c2ef51636de71cc01c212c121c6160003813082037d308202e6a003020102020312bbe6300d06092a864886f70d0101050500304e310b30090603550406130255533110300e060355040a130745717569666178312d302b060355040b1324457175696661782053656375726520436572746966696361746520417574686f72697479301e170d3032303532313034303030305a170d3138303832313034303030305a3042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c20434130820122300d06092a864886f70d01010105000382010f003082010a0282010100dacc186330fdf417231a567e5bdf3c6c38e471b77891d4bca1d84cf8a843b603e94d21070888da582f663929bd05788b9d38e805b76a7e71a4e6c460a6b0ef80e489280f9e25d6ed83f3ada691c798c9421835149dad9846922e4fcaf18743c11695572d50ef892d807a57adf2ee5f6bd2008db914f8141535d9c046a37b72c891bfc9552bcdd0973e9c2664ccdfce831971ca4ee6d4d57ba919cd55dec8ecd25e3853e55c4f8c2dfe502336fc66e6cb8ea4391900b7950239910b0efe382ed11d059af64d3e6f0f071daf2c1e8f6039e2fa36531339d45e262bdb3da814bd32eb180328520471e5ab333de138bb073684629c79ea1630f45fc02be8716be4f90203010001a381f03081ed301f0603551d2304183016801448e668f92bd2b295d747d82320104f3398909fd4301d0603551d0e04160414c07a98688d89fbab05640c117daa7d65b8cacc4e300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106303a0603551d1f04333031302fa02da02b8629687474703a2f2f63726c2e67656f74727573742e636f6d2f63726c732f73656375726563612e63726c304e0603551d200447304530430604551d2000303b303906082b06010505070201162d68747470733a2f2f7777772e67656f74727573742e636f6d2f7265736f75726365732f7265706f7369746f7279300d06092a864886f70d01010505000381810076e1126e4e4b1612863006b28108cff008c7c7717e66eec2edd43b1ffff0f0c84ed64338b0b9307d18d05583a26acb36119ce84866a36d7fb813d447fe8b5a5c73fcaed91b321938ab973414aa96d2eba31c140849b6bbe591ef8336eb1d566fcadabc736390e47f7b3e22cb3d07ed5f38749ce303504ea1af98ee61f2843f12".decode('hex')
        testpacket = TLSPacket(rawdata=testpacket_raw)
        print("certificate:\n %s" % (testpacket.display_string()))

    def test_packet_4(self):
        """ cke """
        testpacket_raw = "160303002510000021209518ddda41a032652a2b5c43f55499fa967216470434ddc51938f32dda760e3d14030300010116030300a00000000000000000bd3a0b43099a6d9c42892302408e3e9a6d0e64b77ae0002341142e8e81711b64ad05f823b187c7032f9c062be3507aebb15345929017c0d8d0b3ba62cbd1f661b5b50b3dfeccabc67a1be492c0cbe39dda0102570e5d2069ac9b2eb06b361c473618d2f0f6971327e179ea94e16f9b257c795787cc47c6f9d3f4ec913068e685752d5eca611d6136f0115f3cce8f24b0feb75c369cf5312a160303002800000000000000015cb76fceb451d1ae011bebdd72eafdd615903c717822d7908ff719541f1ec0c8".decode('hex')
        testpacket = TLSPacket(rawdata=testpacket_raw)
        print("client key exchange:\n %s" % (testpacket.display_string()))

if __name__ == '__main__':
    unittest.main()

