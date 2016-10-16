"""
TLS (Transport Layer Security) SCAPYLAMENTO
"""


#from chunk import TemplateChunk, EnumPackChunk, ValuePackChunk, CStringChunk, X3ByteIntPackChunk, BinaryDataChunk
#from chunk import ListChunk
from streamChunk import *
from inet import IPPackChunk

import struct
import socket
import random
import time

from ssltls_definitions import *

from Crypto.PublicKey import RSA, DSA
from Crypto.Hash import HMAC, SHA256, SHA
from Crypto.Cipher.PKCS1_v1_5 import PKCS115_Cipher
from Crypto.Cipher import AES, DES3

# for decoding certificates
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from binascii import a2b_base64


def guesspayload(*args, **kwargs):
    """ a guess content_typeFD Saf/DSA??? """
    print("guesspayload %s" % (kwargs))
    parent = kwargs['parent']
    rawdata = kwargs['rawdata']
    print("guess based on content type: %s" % parent.content_type)

    if parent.content_type.value == 22:
        handshake_type = struct.unpack('h', rawdata[:2])[0]
        if handshake_type == 1:
            print("guess based on handshake_type: %s" % handshake_type)
            print("return cluienthello")
            return ClientHello(*args, **kwargs)
#        else:
#            return TLS_Handshake(*args, **kwargs)
    else:
        raise Exception("Failed to guess payload")
        return None

    #self.length_fmt = length_fmt


class TLSPacket(TemplateChunk):
    """ The header portion of a SSL/TLS packet """
    name = "TLS Packet"
    template = [(EnumPackChunk, {"name": "content_type", "default": 0, "enum": CONTENT_TYPE, "fmt": "B"}),
                (EnumPackChunk, {"name": "tls_version", "default": 1, "enum": TLS_VERSION, "fmt": ">H"}),
                (ValuePackChunk, {"name": "tls_length", "default": 0, "fmt": ">H"}),
                (guesspayload, {})]


"""
    def guess_payload_class(self, payload):
        if self.content_type == 22:
            handshake_type = struct.unpack('h', payload[:2])[0]
            if handshake_type == 1:
                return Client_Hello
            else:
                return TLS_Handshake
        else:
            return None

    def post_build(self, p, pay):
        p += pay
        if self.tls_length is None:
            # tls_length field is length of the packet minus header
            l = len(p) - 5
            self.tls_length = l
            p = p[:3] + struct.pack('>H', l) + p[5:]

        return p

    def header(self):
        return str(self)[0:5]



class TLS_Appdata(TLSPacket):
    name = "TLS AppData"
    fields_desc = TLSPacket.fields_desc[0:3]
    fields_desc.append(DataField("application_data", None, greedy=True))

    def __init__(self, *args, **kwargs):
        TLSPacket.__init__(self, *args, **kwargs)
        self.content_type = 23


class TLS_Alert(TLSPacket):
    name = "TLS Alert"
    fields_desc = TLSPacket.fields_desc[0:3]
    fields_desc.append(AlertLevelField("alert_level", 0))
    fields_desc.append(AlertDescriptionField("alert_description", 0))

    def __init__(self, *args, **kwargs):
        TLSPacket.__init__(self, *args, **kwargs)
        self.content_type = 21

    def alertString(self):
        return "" + ALERTLEVEL[self.alert_level] + ":" + \
               ALERTDESCRIPTION[self.alert_description]


class TLS_Handshake(Packet):
    name = "TLS Handshake"
    fields_desc = [ByteEnumField("handshake_type", 0, HANDSHAKE_TYPE),
                   X3ByteIntegerField("msg_length", None),
                   DataField("tls_fragment", None, greedy=True)]
"""


class Extension(StreamTemplateChunk):
    name = "TLS Extension"
    template = [(StreamEnumPackChunk, {"name": "extension_type", "default": 1, "enum": EXTENSIONS, "fmt": ">H"}),
                (StreamValuePackChunk, {"name": "extension_len",
                             "default": 0,
                             "length_of": lambda x: x.parent.data.value,
                             "fmt": ">H"}),
                (amBinaryDataChunk, {"name": "extension_data",
                                   "default": 0,
                                   "length_from": lambda x: x.parent.extension_len.value }) ]


class ClientHello(StreamTemplateChunk):
    name = "TLS Client Hello"
    template = [(EnumPackChunk, {"name": "handshake_type", "default": 1, "enum": HANDSHAKE_TYPE, "fmt": "B"}),
                (X3ByteIntPackChunk, {"name": "msg_length", "default": 1}),
                (EnumPackChunk, {"name": "msg_version", "default": 771, "enum": TLS_VERSION, "fmt": ">H"}),
                (BinaryDataChunk, {"name": "gmt_unix_time", "default": 0, "length": 4}),
                (BinaryDataChunk, {"name": "random_bytes", "default": 0, "length": 28}),
                (ValuePackChunk, {"name": "session_id_len",
                              "default": 0,
                              "length_of": lambda x: x.parent.session_id.value,
                              "fmt": "B"}),
                (ListChunk, {"name": "session_id",
                             "length_from": lambda x: x.parent.session_id_len.value,
                             "element_type": (BinaryDataChunk, {"name": "sessionid", "default": 0, "length": 4})}),
                (ValuePackChunk, {"name": "ciphersuite_lst_len",
                              "default": 0,
                              "length_of": lambda x: x.parent.ciphersuite_lst.value,
                              "fmt": ">H"}),
                (ListChunk, {"name": "ciphersuite_lst",
                                       "length_from": lambda x: x.parent.ciphersuite_lst_len.value,
                                       "element_type": (EnumPackChunk, {"name": "cipher", "enum": CIPHER_SUITE, "fmt": "2s"})}),
                (ValuePackChunk, {"name": "compression_lst_len",
                              "default": 0,
                              "length_of": lambda x: x.parent.compression_lst.value,
                              "fmt": "B"}),
                (ListChunk, {"name": "compression_lst",
                                       "length_from": lambda x: x.parent.compression_lst_len.value,
                                       "element_type": (EnumPackChunk, {"name": "compressionmode", "enum": COMPRESSION_METHOD, "fmt": "s"})}),
                (ValuePackChunk, {"name": "extension_lst_len",
                              "default": 0,
                              "length_of": lambda x: x.parent.extension_lst.value,
                              "fmt": ">H"}),
                (ListChunk, {"name": "extension_lst",
                                       "length_from": lambda x: x.parent.extension_lst_len.value,
                                       "element_type": (Extension, {})})]

"""
class ServerHello(TemplateChunk):
    name = "TLS Server Hello"
    template = [(EnumChunk, {"name": "msg_version", "default": 771, "enum": TLS_VERSION, "fmt": ">H"}),
                (BinaryDataChunk, {"name": "gmt_unix_time", "default": 0, "length": 4}),
                (BinaryDataChunk, {"name": "random_bytes", "default": 0, "length": 28}),
                (LengthListChunk, {"name": "session_id", "default": 0, "length_fmt": "B", "element_type":
                    (EnumChunk, {"name": "cipher_suite", "enum": CIPHER_SUITE, "fmt": "2s"}) }),
                (EnumChunk, {"name": "compression", "enum": COMPRESSION_METHOD, "fmt": "2s"}),
                (LengthListChunk, {"name": "extension_lst", "length_fmt": "H", "element_type":
                    (EnumChunk, {"name": "extension", "enum": EXTENSIONTYPE, "fmt": "2s"}) })]
"""
"""
class Certificate(TLS_Handshake):
    name = "Certificate"
    fields_desc = TLS_Handshake.fields_desc[0:5]
    fields_desc.append(X3ByteIntegerFieldLenField("certificates_len", \
                                                  None, length_of="certificates_lst"))
    fields_desc.append(DataField("certificates_lst", "\x00", \
                                 length_from=lambda pkt: pkt.certificates_len))

    def __init__(self, *args, **kwargs):
        TLS_Handshake.__init__(self, *args, **kwargs)
        self.handshake_type = 11

    def get_certificates(self):
        if self.certificates_lst is None:
            return

        certlst = []
        astr = self.certificates_lst
        while len(astr) > 3:
            certlen = struct.unpack(">L", "\x00" + astr[:3])[0]
            certx = astr[3:3 + certlen]
            certlst.append(certx)
            astr = astr[3 + certlen:]

        return certlst

    def set_certificates(self, cert):
        certlen = struct.pack(">L", len(cert))[1:4]
        self.certificates_lst = certlen + cert


class Server_Key_Exchange(TLS_Handshake):
    name = "Server Key Exchance"
    fields_desc = TLS_Handshake.fields_desc[0:5]
    fields_desc.append(DataField("key_exchange", None, greedy=True))

    def __init__(self, *args, **kwargs):
        TLS_Handshake.__init__(self, *args, **kwargs)
        self.handshake_type = 12


class Certificate_Request(TLS_Handshake):
    name = "Certificate Request"
    fields_desc = TLS_Handshake.fields_desc[0:5]
    fields_desc.append(FieldLenField("certificate_types_len", None, fmt=">B",
                                     length_of="certificate_type_lst"))
    fields_desc.append(CertificateTypeListField("certificate_type_lst", "",
                                                length_from=lambda pkt: pkt.certificate_types_len))
    fields_desc.append(FieldLenField("signature_alg_len", None, fmt=">H",
                                     length_of="signature_alg_lst"))
    fields_desc.append(SignatureAlgorithmListField("signature_alg_lst", "",
                                                   length_from=lambda pkt: pkt.signature_alg_len))
    fields_desc.append(FieldLenField("distinguished_names_len", None, fmt=">H",
                                     length_of="distinguished_names_lst"))
    fields_desc.append(DistinguishedNameListField("distinguised_names_lst", "",
                                                  length_from=lambda pkt: pkt.distinguished_names_len))

    def __init__(self, *args, **kwargs):
        TLS_Handshake.__init__(self, *args, **kwargs)
        self.handshake_type = 13


class Server_Hello_Done(TLS_Handshake):
    name = "Server Hello Done"
    fields_desc = TLS_Handshake.fields_desc[0:5]

    def __init__(self, *args, **kwargs):
        TLSPacket.__init__(self, *args, **kwargs)
        self.handshake_type = 14


class Client_Key_Exchange(TLS_Handshake):
    name = "Client Key Exchange"
    fields_desc = TLS_Handshake.fields_desc[0:5]
    fields_desc.append(FieldLenField("key_exchange_len", None, fmt=">H",
                                     length_of="key_exchange"))
    fields_desc.append(DataField("key_exchange", "", \
                                 length_from=lambda pkt: pkt.key_exchange_len))

    def __init__(self, *args, **kwargs):
        TLS_Handshake.__init__(self, *args, **kwargs)
        self.handshake_type = 16


class Certificate_Verify(TLS_Handshake):
    name = "Certificate Verify"
    fields_desc = TLS_Handshake.fields_desc[0:5]
    fields_desc.append(DataField("data", None, greedy=True))

    def __init__(self, *args, **kwargs):
        TLS_Handshake.__init__(self, *args, **kwargs)
        self.handshake_type = 15


class Finished(TLS_Handshake):
    name = "Finished"
    fields_desc = TLS_Handshake.fields_desc[0:5]
    fields_desc.append(DataField("verify_data", None, greedy=True))

    def __init__(self, *args, **kwargs):
        TLS_Handshake.__init__(self, *args, **kwargs)
        self.handshake_type = 20


class Change_Cipher_Spec(TLSPacket):
    name = "Change Cipher Spec"
    fields_desc = TLSPacket.fields_desc[0:3]
    fields_desc.append(ByteField("change_spec", 1))

    def __init__(self, *args, **kwargs):
        TLSPacket.__init__(self, *args, **kwargs)
        self.content_type = 20
"""
