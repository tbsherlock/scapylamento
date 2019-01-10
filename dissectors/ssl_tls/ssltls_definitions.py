"""
TLS (Transport Layer Security) SCAPYLAMENTO defines
"""

#from Crypto.PublicKey import RSA, DSA
#from Crypto.Hash import HMAC, SHA, SHA256, SHA384
#from Crypto.Cipher.PKCS1_v1_5 import PKCS115_Cipher
#from Crypto.Cipher import AES, DES3

# for decoding certificates
#from Crypto.Util.asn1 import DerSequence
#from Crypto.PublicKey import RSA
from binascii import a2b_base64


EXTENSIONS = {0x0000: '(0x0000) server_name',
              0xff01: '(0xff01) renegotiation_info',
              0x0017: '(0x0017) extended master secret',
              0x0023: '(0x0023) SessionTicket TLS' }

CONTENT_TYPE = {20: '(20) Change Cipher Spec',
                21: '(21) Alert',
                22: '(22) Handshake',
                23: '(23) Application Data'}

TLS_VERSION = {0x0303: '(0x0303) TLS 1.2',
               0x0302: '(0x0302) TLS 1.1',
               0x0301: '(0x0301) TLS 1.0',
               0x0300: '(0x3000) SSL 3.0'}

HANDSHAKE_TYPE = {0:  '(0)  hello_request',
                  1:  '(1)  client_hello',
                  2:  '(2)  server_hello',
                  11: '(11) certificate',
                  12: '(12) server_key_exchange',
                  13: '(13) certificate_request',
                  14: '(14) server_hello_done',
                  15: '(15) certificate_verify',
                  16: '(16) client_key_exchange',
                  20: '(20) finished' }

CIPHERTYPE = {'STREAM': 1,
              'BLOCK':  2,
              'AEAD':   3}

AUTHMODE = {'RSA':       1,
            'DHE_RSA':   2,
            'DH_RSA':    3,
            'RSA_PSK':   4,
            'ECDH_RSA':  5,
            'ECDHE_RSA': 6}

COMPRESSION_METHOD = {'null':    0,
                      'DEFLATE': 1}

CLIENT_CERTIFICATE_TYPE = {1: 'rsa_sign',
                           2: 'dss_sign',
                           3: 'rsa_fixed_dh',
                           4: 'dss_fixed_dh',
                           5: 'rsa_ephemeral_dh_RESERVED',
                           6: 'dss_ephemeral_dh_RESERVED',
                           20: 'fortezza_dms_RESERVED'}

CIPHER_SUITE = {'\x00\x00': 'TLS_NULL_WITH_NULL_NULL',
                '\x00\x01': 'TLS_RSA_WITH_NULL_MD5',
                '\x00\x02': 'TLS_RSA_WITH_NULL_SHA',
                '\x00\x03': 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
                '\x00\x04': 'TLS_RSA_WITH_RC4_128_MD5',
                '\x00\x05': 'TLS_RSA_WITH_RC4_128_SHA',
                '\x00\x06': 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
                '\x00\x07': 'TLS_RSA_WITH_IDEA_CBC_SHA',
                '\x00\x08': 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
                '\x00\x09': 'TLS_RSA_WITH_DES_CBC_SHA',
                '\x00\x0A': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                '\x00\x0b': 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
                '\x00\x0c': 'TLS_DH_DSS_WITH_DES_CBC_SHA',
                '\x00\x0d': 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
                '\x00\x0e': 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
                '\x00\x0f': 'TLS_DH_RSA_WITH_DES_CBC_SHA',
                '\x00\x10': 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
                '\x00\x11': 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
                '\x00\x12': 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
                '\x00\x13': 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
                '\x00\x14': 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
                '\x00\x15': 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
                '\x00\x16': 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
                '\x00\x17': 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
                '\x00\x18': 'TLS_DH_anon_WITH_RC4_128_MD5',
                '\x00\x19': 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
                '\x00\x1a': 'TLS_DH_anon_WITH_DES_CBC_SHA',
                '\x00\x1b': 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
                # 0x00, 0x1c-1d reserved to avoid conflicts with SSLv3
                '\x00\x1e': 'TLS_KRB5_WITH_DES_CBC_SHA',
                '\x00\x1f': 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
                '\x00\x20': 'TLS_KRB5_WITH_RC4_128_SHA',
                '\x00\x21': 'TLS_KRB5_WITH_IDEA_CBC_SHA',
                '\x00\x22': 'TLS_KRB5_WITH_DES_CBC_MD5',
                '\x00\x23': 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
                '\x00\x24': 'TLS_KRB5_WITH_RC4_128_MD5',
                '\x00\x25': 'TLS_KRB5_WITH_IDEA_CBC_MD5',
                '\x00\x26': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
                '\x00\x27': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
                '\x00\x28': 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
                '\x00\x29': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
                '\x00\x2a': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
                '\x00\x2b': 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
                '\x00\x2c': 'TLS_PSK_WITH_NULL_SHA',
                '\x00\x2d': 'TLS_DHE_PSK_WITH_NULL_SHA',
                '\x00\x2e': 'TLS_RSA_PSK_WITH_NULL_SHA',
                '\x00\x2f': 'TLS_RSA_WITH_AES_128_CBC_SHA',
                '\x00\x30': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
                '\x00\x31': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
                '\x00\x32': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
                '\x00\x33': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
                '\x00\x34': 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
                '\x00\x35': 'TLS_RSA_WITH_AES_256_CBC_SHA',
                '\x00\x36': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
                '\x00\x37': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
                '\x00\x38': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
                '\x00\x39': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
                '\x00\x3a': 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
                '\x00\x3B': 'TLS_RSA_WITH_NULL_SHA256',
                '\x00\x3C': 'TLS_RSA_AES_256_CBC_SHA256',
                '\x00\x3D': 'TLS_RSA_AES_256_CBC_SHA256',
                '\x00\x3e': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
                '\x00\x3f': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
                '\x00\x40': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
                '\x00\x41': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
                '\x00\x42': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
                '\x00\x43': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
                '\x00\x44': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
                '\x00\x45': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
                '\x00\x46': 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
                # 0x00,0x47-4F	Reserved to avoid conflicts with deployed implementations
                # 0x00,0x50-58	Reserved to avoid conflicts
                # 0x00,0x59-5C	Reserved to avoid conflicts with deployed implementations
                # 0x00,0x5D-5F	Unassigned
                # 0x00,0x60-66	Reserved to avoid conflicts with widely deployed implementations
                '\x00\x67': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
                '\x00\x68': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
                '\x00\x69': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
                '\x00\x6a': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
                '\x00\x6b': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
                '\x00\x6c': 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
                '\x00\x6d': 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
                # 0x00,0x6E-83	Unassigned
                '\x00\x84': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
                '\x00\x85': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
                '\x00\x86': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
                '\x00\x87': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
                '\x00\x88': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
                '\x00\x89': 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
                '\x00\x8a': 'TLS_PSK_WITH_RC4_128_SHA',
                '\x00\x8b': 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
                '\x00\x8c': 'TLS_PSK_WITH_AES_128_CBC_SHA',
                '\x00\x8d': 'TLS_PSK_WITH_AES_256_CBC_SHA',
                '\x00\x8e': 'TLS_DHE_PSK_WITH_RC4_128_SHA',
                '\x00\x8f': 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
                '\x00\x90': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
                '\x00\x91': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
                '\x00\x92': 'TLS_RSA_PSK_WITH_RC4_128_SHA',
                '\x00\x93': 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
                '\x00\x94': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
                '\x00\x95': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
                '\x00\x96': 'TLS_RSA_WITH_SEED_CBC_SHA',
                '\x00\x97': 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
                '\x00\x98': 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
                '\x00\x99': 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
                '\x00\x9a': 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
                '\x00\x9b': 'TLS_DH_anon_WITH_SEED_CBC_SHA',
                '\x00\x9c': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
                '\x00\x9d': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
                '\x00\x9e': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
                '\x00\x9f': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                '\x00\xA0': 'DH_RSA_WITH_AES_128_GCM_SHA256',
                '\x00\xA1': 'DH_RSA_WITH_AES_256_GCM_SHA384',
                '\x00\xA2': 'DHE_DSS_WITH_AES_128_GCM_SHA256',
                '\x00\xA3': 'DHE_DSS_WITH_AES_256_GCM_SHA384',
                '\x00\xA4': 'DH_DSS_WITH_AES_128_GCM_SHA256',
                '\x00\xA5': 'DH_DSS_WITH_AES_256_GCM_SHA384',
                '\x00\xA6': 'DH_anon_WITH_AES_128_GCM_SHA256',
                '\x00\xA7': 'DH_anon_WITH_AES_256_GCM_SHA384',
                '\x00\xA8': 'PSK_WITH_AES_128_GCM_SHA256',
                '\x00\xA9': 'PSK_WITH_AES_256_GCM_SHA384',
                '\x00\xAA': 'DHE_PSK_WITH_AES_128_GCM_SHA256',
                '\x00\xAB': 'DHE_PSK_WITH_AES_256_GCM_SHA384',
                '\x00\xAC': 'RSA_PSK_WITH_AES_128_GCM_SHA256',
                '\x00\xAD': 'RSA_PSK_WITH_AES_256_GCM_SHA384',
                '\x00\xAE': 'PSK_WITH_AES_128_CBC_SHA256',
                '\x00\xAF': 'PSK_WITH_AES_256_CBC_SHA384',
                '\x00\xB0': 'PSK_WITH_NULL_SHA256',
                '\x00\xB1': 'PSK_WITH_NULL_SHA384',
                '\x00\xB2': 'DHE_PSK_WITH_AES_128_CBC_SHA256',
                '\x00\xB3': 'DHE_PSK_WITH_AES_256_CBC_SHA384',
                '\x00\xB4': 'DHE_PSK_WITH_NULL_SHA256',
                '\x00\xB5': 'DHE_PSK_WITH_NULL_SHA384',
                '\x00\xB6': 'RSA_PSK_WITH_AES_128_CBC_SHA256',
                '\x00\xB7': 'RSA_PSK_WITH_AES_256_CBC_SHA384',
                '\x00\xB8': 'RSA_PSK_WITH_NULL_SHA256',
                '\x00\xB9': 'RSA_PSK_WITH_NULL_SHA384',
                '\x00\xBA': 'RSA_WITH_CAMELLIA_128_CBC_SHA256',
                '\x00\xBB': 'DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
                '\x00\xBC': 'DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                '\x00\xBD': 'DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
                '\x00\xBE': 'DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                '\x00\xBF': 'DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
                '\x00\xC0': 'RSA_WITH_CAMELLIA_256_CBC_SHA256',
                '\x00\xC1': 'DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
                '\x00\xC2': 'DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
                '\x00\xC3': 'DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
                '\x00\xC4': 'DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
                '\x00\xC5': 'DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
                # \x00\xC6-FE	Unassigned
                '\x00\xFF': 'EMPTY_RENEGOTIATION_INFO_SCSV',
                # \x01-BF,*	Unassigned
                '\xC0\x01': 'ECDH_ECDSA_WITH_NULL_SHA',
                '\xC0\x02': 'ECDH_ECDSA_WITH_RC4_128_SHA',
                '\xC0\x03': 'ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
                '\xC0\x04': 'ECDH_ECDSA_WITH_AES_128_CBC_SHA',
                '\xC0\x05': 'ECDH_ECDSA_WITH_AES_256_CBC_SHA',
                '\xC0\x06': 'ECDHE_ECDSA_WITH_NULL_SHA',
                '\xC0\x07': 'ECDHE_ECDSA_WITH_RC4_128_SHA',
                '\xC0\x08': 'ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
                '\xC0\x09': 'ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
                '\xc0\x0A': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
                '\xC0\x0B': 'ECDH_RSA_WITH_NULL_SHA',
                '\xC0\x0C': 'ECDH_RSA_WITH_RC4_128_SHA',
                '\xC0\x0D': 'ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
                '\xC0\x0E': 'ECDH_RSA_WITH_AES_128_CBC_SHA',
                '\xC0\x0F': 'ECDH_RSA_WITH_AES_256_CBC_SHA',
                '\xC0\x10': 'ECDHE_RSA_WITH_NULL_SHA',
                '\xC0\x11': 'ECDHE_RSA_WITH_RC4_128_SHA',
                '\xC0\x12': 'ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
                '\xC0\x13': 'ECDHE_RSA_WITH_AES_128_CBC_SHA',
                '\xC0\x14': 'ECDHE_RSA_WITH_AES_256_CBC_SHA',
                '\xC0\x15': 'ECDH_anon_WITH_NULL_SHA',
                '\xC0\x16': 'ECDH_anon_WITH_RC4_128_SHA',
                '\xC0\x17': 'ECDH_anon_WITH_3DES_EDE_CBC_SHA',
                '\xC0\x18': 'ECDH_anon_WITH_AES_128_CBC_SHA',
                '\xC0\x19': 'ECDH_anon_WITH_AES_256_CBC_SHA',
                '\xC0\x1A': 'SRP_SHA_WITH_3DES_EDE_CBC_SHA',
                '\xC0\x1B': 'SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
                '\xC0\x1C': 'SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
                '\xC0\x1D': 'SRP_SHA_WITH_AES_128_CBC_SHA',
                '\xC0\x1E': 'SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
                '\xC0\x1F': 'SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
                '\xC0\x20': 'SRP_SHA_WITH_AES_256_CBC_SHA',
                '\xC0\x21': 'SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
                '\xC0\x22': 'SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
                '\xC0\x23': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
                '\xC0\x24': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA256',
                '\xC0\x25': 'ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
                '\xC0\x26': 'ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
                '\xC0\x27': 'ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                '\xC0\x28': 'ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                '\xC0\x29': 'ECDH_RSA_WITH_AES_128_CBC_SHA256',
                '\xC0\x2A': 'ECDH_RSA_WITH_AES_256_CBC_SHA384',
                '\xC0\x2B': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                '\xC0\x2C': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                '\xC0\x2D': 'ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
                '\xC0\x2E': 'ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
                '\xC0\x2F': 'ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                '\xC0\x30': 'ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                '\xC0\x31': 'ECDH_RSA_WITH_AES_128_GCM_SHA256',
                '\xC0\x32': 'ECDH_RSA_WITH_AES_256_GCM_SHA384',
                '\xC0\x33': 'ECDHE_PSK_WITH_RC4_128_SHA',
                '\xC0\x34': 'ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
                '\xC0\x35': 'ECDHE_PSK_WITH_AES_128_CBC_SHA',
                '\xC0\x36': 'ECDHE_PSK_WITH_AES_256_CBC_SHA',
                '\xC0\x37': 'ECDHE_PSK_WITH_AES_128_CBC_SHA256',
                '\xC0\x38': 'ECDHE_PSK_WITH_AES_256_CBC_SHA384',
                '\xC0\x39': 'ECDHE_PSK_WITH_NULL_SHA',
                '\xC0\x3A': 'ECDHE_PSK_WITH_NULL_SHA256',
                '\xC0\x3B': 'ECDHE_PSK_WITH_NULL_SHA384',
                '\xC0\x3C': 'RSA_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x3D': 'RSA_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x3E': 'DH_DSS_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x3F': 'DH_DSS_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x40': 'DH_RSA_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x41': 'DH_RSA_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x42': 'DHE_DSS_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x43': 'DHE_DSS_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x44': 'DHE_RSA_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x45': 'DHE_RSA_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x46': 'DH_anon_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x47': 'DH_anon_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x48': 'ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x49': 'ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x4A': 'ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x4B': 'ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x4C': 'ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x4D': 'ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x4E': 'ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x4F': 'ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x50': 'RSA_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x51': 'RSA_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x52': 'DHE_RSA_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x53': 'DHE_RSA_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x54': 'DH_RSA_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x55': 'DH_RSA_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x56': 'DHE_DSS_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x57': 'DHE_DSS_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x58': 'DH_DSS_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x59': 'DH_DSS_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x5A': 'DH_anon_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x5B': 'DH_anon_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x5C': 'ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x5D': 'ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x5E': 'ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x5F': 'ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x60': 'ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x61': 'ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x62': 'ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x63': 'ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x64': 'PSK_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x65': 'PSK_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x66': 'DHE_PSK_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x67': 'DHE_PSK_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x68': 'RSA_PSK_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x69': 'RSA_PSK_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x6A': 'PSK_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x6B': 'PSK_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x6C': 'DHE_PSK_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x6D': 'DHE_PSK_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x6E': 'RSA_PSK_WITH_ARIA_128_GCM_SHA256',
                '\xC0\x6F': 'RSA_PSK_WITH_ARIA_256_GCM_SHA384',
                '\xC0\x70': 'ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
                '\xC0\x71': 'ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
                '\xC0\x72': 'ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
                '\xC0\x73': 'ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
                '\xC0\x74': 'ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
                '\xC0\x75': 'ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
                '\xC0\x76': 'ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                '\xC0\x77': 'ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
                '\xC0\x78': 'ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                '\xC0\x79': 'ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
                '\xC0\x7A': 'RSA_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x7B': 'RSA_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x7C': 'DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x7D': 'DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x7E': 'DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x7F': 'DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x80': 'DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x81': 'DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x82': 'DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x83': 'DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x84': 'DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x85': 'DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x86': 'ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x87': 'ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x88': 'ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x89': 'ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x8A': 'ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x8B': 'ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x8C': 'ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x8D': 'ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x8E': 'PSK_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x8F': 'PSK_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x90': 'DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x91': 'DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x92': 'RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
                '\xC0\x93': 'RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
                '\xC0\x94': 'PSK_WITH_CAMELLIA_128_CBC_SHA256',
                '\xC0\x95': 'PSK_WITH_CAMELLIA_256_CBC_SHA384',
                '\xC0\x96': 'DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                '\xC0\x97': 'DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                '\xC0\x98': 'RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                '\xC0\x99': 'RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                '\xC0\x9A': 'ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                '\xC0\x9B': 'ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                '\xC0\x9C': 'RSA_WITH_AES_128_CCM',
                '\xC0\x9D': 'RSA_WITH_AES_256_CCM',
                '\xC0\x9E': 'DHE_RSA_WITH_AES_128_CCM',
                '\xC0\x9F': 'DHE_RSA_WITH_AES_256_CCM',
                '\xC0\xA0': 'RSA_WITH_AES_128_CCM_8',
                '\xC0\xA1': 'RSA_WITH_AES_256_CCM_8',
                '\xC0\xA2': 'DHE_RSA_WITH_AES_128_CCM_8',
                '\xC0\xA3': 'DHE_RSA_WITH_AES_256_CCM_8',
                '\xC0\xA4': 'PSK_WITH_AES_128_CCM',
                '\xC0\xA5': 'PSK_WITH_AES_256_CCM',
                '\xC0\xA6': 'DHE_PSK_WITH_AES_128_CCM',
                '\xC0\xA7': 'DHE_PSK_WITH_AES_256_CCM',
                '\xC0\xA8': 'PSK_WITH_AES_128_CCM_8',
                '\xC0\xA9': 'PSK_WITH_AES_256_CCM_8',
                '\xC0\xAA': 'PSK_DHE_WITH_AES_128_CCM_8',
                '\xC0\xAB': 'PSK_DHE_WITH_AES_256_CCM_8',
                # \xC0\xAC-FF	Unassigned
                # \xC1-FD,*	Unassigned
                # \xFE,\x00-FD	Unassigned
                # \xFE,\xFE-FF	Reserved to avoid conflicts with widely deployed implementations		[Pasi_Eronen]
                # \xFF,\x00-FF	Reserved for Private Use		[RFC5246]
                '\x00\xff': 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV' }
"""
CIPHER_SUITES = [
    {'id': '\x00\x00',
     'name': 'TLS_NULL_WITH_NULL_NULL'},

    {'id': '\x00\x01',
     'name': 'TLS_RSA_WITH_NULL_MD5'},

    {'id': '\x00\x02',
     'name': 'TLS_RSA_WITH_NULL_SHA'},

    {'id': '\x00\x03',
     'name': 'TLS_RSA_EXPORT_WITH_RC4_40_MD5'},

    {'id': '\x00\x04',
     'name': 'TLS_RSA_WITH_RC4_128_MD5'},

    {'id': '\x00\x05',
     'name': 'TLS_RSA_WITH_RC4_128_SHA'},

    {'id': '\x00\x06',
     'name': 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5'},

    {'id': '\x00\x07',
     'name': 'TLS_RSA_WITH_IDEA_CBC_SHA'},

    {'id': '\x00\x08',
     'name': 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA'},

    {'id': '\x00\x09',
     'name': 'TLS_RSA_WITH_DES_CBC_SHA',
     'authentication': RSA,
     # 'authentication_mode': 	AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     #  'cipher_mode':		DES.MODE_CBC,
     'enc_key_length': 8,
     #  'block_length':		DES.block_size,
     #  'fixed_iv_length':	DES.block_size,
     #  'record_iv_length':	DES.block_size,
     'mac_algorithm': SHA,
     'mac_length': SHA.digest_size,
     'mac_key_length': SHA.digest_size},

    {'id': '\x00\x0A',
     'name': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
     'authentication': RSA,
     'authentication_mode': AUTHMODE['RSA'],
     'bulk_cipher_algorithm': DES3,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 24,
     'block_length': DES3.block_size,
     'fixed_iv_length': DES3.block_size,
     'record_iv_length': DES3.block_size,
     'mac_algorithm': SHA,
     'mac_length': SHA.digest_size,
     'mac_key_length': SHA.digest_size},

    {'id': '\x00\x0b',
     'name': 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA'},

    {'id': '\x00\x0c',
     'name': 'TLS_DH_DSS_WITH_DES_CBC_SHA'},

    {'id': '\x00\x0d',
     'name': 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\x00\x0e',
     'name': 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA'},

    {'id': '\x00\x0f',
     'name': 'TLS_DH_RSA_WITH_DES_CBC_SHA'},

    {'id': '\x00\x10',
     'name': 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\x00\x11',
     'name': 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA'},

    {'id': '\x00\x12',
     'name': 'TLS_DHE_DSS_WITH_DES_CBC_SHA'},

    {'id': '\x00\x13',
     'name': 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\x00\x14',
     'name': 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA'},

    {'id': '\x00\x15',
     'name': 'TLS_DHE_RSA_WITH_DES_CBC_SHA'},

    {'id': '\x00\x16',
     'name': 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\x00\x17',
     'name': 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5'},

    {'id': '\x00\x18',
     'name': 'TLS_DH_anon_WITH_RC4_128_MD5'},

    {'id': '\x00\x19',
     'name': 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA'},

    {'id': '\x00\x1a',
     'name': 'TLS_DH_anon_WITH_DES_CBC_SHA'},

    {'id': '\x00\x1b',
     'name': 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA'},

    # 0x00, 0x1c-1d reserved to avoid conflicts with SSLv3

    {'id': '\x00\x1e',
     'name': 'TLS_KRB5_WITH_DES_CBC_SHA'},

    {'id': '\x00\x1f',
     'name': 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\x00\x20',
     'name': 'TLS_KRB5_WITH_RC4_128_SHA'},

    {'id': '\x00\x21',
     'name': 'TLS_KRB5_WITH_IDEA_CBC_SHA'},

    {'id': '\x00\x22',
     'name': 'TLS_KRB5_WITH_DES_CBC_MD5'},

    {'id': '\x00\x23',
     'name': 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5'},

    {'id': '\x00\x24',
     'name': 'TLS_KRB5_WITH_RC4_128_MD5'},

    {'id': '\x00\x25',
     'name': 'TLS_KRB5_WITH_IDEA_CBC_MD5'},

    {'id': '\x00\x26',
     'name': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA'},

    {'id': '\x00\x27',
     'name': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA'},

    {'id': '\x00\x28',
     'name': 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA'},

    {'id': '\x00\x29',
     'name': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5'},

    {'id': '\x00\x2a',
     'name': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5'},

    {'id': '\x00\x2b',
     'name': 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5'},

    {'id': '\x00\x2c',
     'name': 'TLS_PSK_WITH_NULL_SHA'},

    {'id': '\x00\x2d',
     'name': 'TLS_DHE_PSK_WITH_NULL_SHA'},

    {'id': '\x00\x2e',
     'name': 'TLS_RSA_PSK_WITH_NULL_SHA'},

    {'id': '\x00\x2f',
     'name': 'TLS_RSA_WITH_AES_128_CBC_SHA',
     'authentication': RSA,
     'authentication_mode': AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 16,
     'block_length': AES.block_size,
     'fixed_iv_length': AES.block_size,
     'record_iv_length': AES.block_size,
     'mac_algorithm': SHA,
     'mac_length': SHA.digest_size,
     'mac_key_length': SHA.digest_size},

    {'id': '\x00\x30',
     'name': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA'},

    {'id': '\x00\x31',
     'name': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA'},

    {'id': '\x00\x32',
     'name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
     #  'authentication': 		DSS,
     #  'authentication_mode': 	AUTHMODE['DHE_DSS'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 16,
     'block_length': 16,
     'fixed_iv_length': 16,
     'record_iv_length': 16,
     'mac_algorithm': SHA,
     'mac_length': 20,
     'mac_key_length': 20},

    {'id': '\x00\x33',
     'name': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
     'authentication': RSA,
     'authentication_mode': AUTHMODE['DHE_RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 16,
     'block_length': 16,
     'fixed_iv_length': 16,
     'record_iv_length': 16,
     'mac_algorithm': SHA,
     'mac_length': 20,
     'mac_key_length': 20},

    {'id': '\x00\x34',
     'name': 'TLS_DH_anon_WITH_AES_128_CBC_SHA'},

    {'id': '\x00\x35',
     'name': 'TLS_RSA_WITH_AES_256_CBC_SHA'},

    {'id': '\x00\x36',
     'name': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA'},

    {'id': '\x00\x37',
     'name': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA'},

    {'id': '\x00\x38',
     'name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA'},

    {'id': '\x00\x39',
     'name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
     'authentication': RSA,
     'authentication_mode': AUTHMODE['DHE_RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 32,
     'block_length': AES.block_size,
     'fixed_iv_length': AES.block_size,
     'record_iv_length': AES.block_size,
     'mac_algorithm': SHA,
     'mac_length': SHA.digest_size,
     'mac_key_length': SHA.digest_size},

    {'id': '\x00\x3a',
     'name': 'TLS_DH_anon_WITH_AES_256_CBC_SHA'},

    {'id': '\x00\x3B',
     'name': 'TLS_RSA_WITH_NULL_SHA256',
     'authentication': RSA,
     # 'authentication_mode': 	AUTHMODE['RSA'],
     'bulk_cipher_algorithm': None,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': 0,
     'enc_key_length': 0,
     'block_length': 0,
     'fixed_iv_length': 0,
     'record_iv_length': 0,
     'mac_algorithm': SHA256,
     'mac_length': 32,
     'mac_key_length': 32},

    {'id': '\x00\x3C',
     'name': 'TLS_RSA_AES_256_CBC_SHA256',
     'authentication': RSA,
     'authentication_mode': AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 32,
     'block_length': AES.block_size,
     'fixed_iv_length': AES.block_size,
     'record_iv_length': AES.block_size,
     'mac_algorithm': SHA256,
     'mac_length': SHA256.digest_size,
     'mac_key_length': SHA256.digest_size},

    {'id': '\x00\x3D',
     'name': 'TLS_RSA_AES_256_CBC_SHA256',
     'authentication': RSA,
     'authentication_mode': AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 32,
     'block_length': AES.block_size,
     'fixed_iv_length': AES.block_size,
     'record_iv_length': AES.block_size,
     'mac_algorithm': SHA256,
     'mac_length': SHA256.digest_size,
     'mac_key_length': SHA256.digest_size},

    {'id': '\x00\x3e',
     'name': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256'},

    {'id': '\x00\x3f',
     'name': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256'},

    {'id': '\x00\x40',
     'name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'},

    {'id': '\x00\x41',
     'name': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA'},

    {'id': '\x00\x42',
     'name': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA'},

    {'id': '\x00\x43',
     'name': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA'},

    {'id': '\x00\x44',
     'name': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA'},

    {'id': '\x00\x45',
     'name': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA'},

    {'id': '\x00\x46',
     'name': 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA'},

    # 0x00,0x47-4F	Reserved to avoid conflicts with deployed implementations
    # 0x00,0x50-58	Reserved to avoid conflicts
    # 0x00,0x59-5C	Reserved to avoid conflicts with deployed implementations
    # 0x00,0x5D-5F	Unassigned
    # 0x00,0x60-66	Reserved to avoid conflicts with widely deployed implementations

    {'id': '\x00\x67',
     'name': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
     'authentication': RSA,
     # 'authentication_mode': 	AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 16,
     'block_length': 16,
     'fixed_iv_length': 16,
     'record_iv_length': 16,
     'mac_algorithm': SHA256,
     'mac_length': 32,
     'mac_key_length': 32},

    {'id': '\x00\x68',
     'name': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256'},

    {'id': '\x00\x69',
     'name': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256'},

    {'id': '\x00\x6a',
     'name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'},

    {'id': '\x00\x6b',
     'name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
     'authentication': RSA,
     'authentication_mode': AUTHMODE['DHE_RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'enc_key_length': 32,
     'block_length': AES.block_size,
     'fixed_iv_length': AES.block_size,
     'record_iv_length': AES.block_size,
     'mac_algorithm': SHA256,
     'mac_length': SHA256.digest_size,
     'mac_key_length': SHA256.digest_size},

    {'id': '\x00\x6c',
     'name': 'TLS_DH_anon_WITH_AES_128_CBC_SHA256'},

    {'id': '\x00\x6d',
     'name': 'TLS_DH_anon_WITH_AES_256_CBC_SHA256'},

    # 0x00,0x6E-83	Unassigned

    {'id': '\x00\x84',
     'name': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA'},

    {'id': '\x00\x85',
     'name': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA'},

    {'id': '\x00\x86',
     'name': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA'},

    {'id': '\x00\x87',
     'name': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA'},

    {'id': '\x00\x88',
     'name': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA'},

    {'id': '\x00\x89',
     'name': 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA'},

    {'id': '\x00\x8a',
     'name': 'TLS_PSK_WITH_RC4_128_SHA'},

    {'id': '\x00\x8b',
     'name': 'TLS_PSK_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\x00\x8c',
     'name': 'TLS_PSK_WITH_AES_128_CBC_SHA'},

    {'id': '\x00\x8d',
     'name': 'TLS_PSK_WITH_AES_256_CBC_SHA'},

    {'id': '\x00\x8e',
     'name': 'TLS_DHE_PSK_WITH_RC4_128_SHA'},

    {'id': '\x00\x8f',
     'name': 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\x00\x90',
     'name': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA'},

    {'id': '\x00\x91',
     'name': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA'},

    {'id': '\x00\x92',
     'name': 'TLS_RSA_PSK_WITH_RC4_128_SHA'},

    {'id': '\x00\x93',
     'name': 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\x00\x94',
     'name': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA'},

    {'id': '\x00\x95',
     'name': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA'},

    {'id': '\x00\x96',
     'name': 'TLS_RSA_WITH_SEED_CBC_SHA'},

    {'id': '\x00\x97',
     'name': 'TLS_DH_DSS_WITH_SEED_CBC_SHA'},

    {'id': '\x00\x98',
     'name': 'TLS_DH_RSA_WITH_SEED_CBC_SHA'},

    {'id': '\x00\x99',
     'name': 'TLS_DHE_DSS_WITH_SEED_CBC_SHA'},

    {'id': '\x00\x9a',
     'name': 'TLS_DHE_RSA_WITH_SEED_CBC_SHA'},

    {'id': '\x00\x9b',
     'name': 'TLS_DH_anon_WITH_SEED_CBC_SHA'},

    {'id': '\x00\x9c',
     'name': 'TLS_RSA_WITH_AES_128_GCM_SHA256'},

    {'id': '\x00\x9d',
     'name': 'TLS_RSA_WITH_AES_256_GCM_SHA384'},

    {'id': '\x00\x9e',
     'name': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
     'authentication': RSA,
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],  # ?
     #  'cipher_mode':		AES.MODE_GCM,
     'enc_key_length': 32,
     'block_length': 16,
     'fixed_iv_length': 16,
     'record_iv_length': 16,
     'mac_algorithm': SHA256,
     'mac_length': 32,
     'mac_key_length': 32},

    {'id': '\x00\x9f',
     'name': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
     'authentication': RSA,
     # 'authentication_mode': 	AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     #  'cipher_mode':		AES.MODE_GCM,
     'enc_key_length': 48,
     'block_length': 16,
     'fixed_iv_length': 16,
     'record_iv_length': 16,
     'mac_algorithm': SHA384,
     'mac_length': 32,
     'mac_key_length': 32},

    {'id': '\x00\xA0',
     'name': 'DH_RSA_WITH_AES_128_GCM_SHA256'},

    {'id': '\x00\xA1',
     'name': 'DH_RSA_WITH_AES_256_GCM_SHA384'},

    {'id': '\x00\xA2',
     'name': 'DHE_DSS_WITH_AES_128_GCM_SHA256'},

    {'id': '\x00\xA3',
     'name': 'DHE_DSS_WITH_AES_256_GCM_SHA384'},

    {'id': '\x00\xA4',
     'name': 'DH_DSS_WITH_AES_128_GCM_SHA256'},

    {'id': '\x00\xA5',
     'name': 'DH_DSS_WITH_AES_256_GCM_SHA384'},

    {'id': '\x00\xA6',
     'name': 'DH_anon_WITH_AES_128_GCM_SHA256'},

    {'id': '\x00\xA7',
     'name': 'DH_anon_WITH_AES_256_GCM_SHA384'},

    {'id': '\x00\xA8',
     'name': 'PSK_WITH_AES_128_GCM_SHA256'},

    {'id': '\x00\xA9',
     'name': 'PSK_WITH_AES_256_GCM_SHA384'},

    {'id': '\x00\xAA',
     'name': 'DHE_PSK_WITH_AES_128_GCM_SHA256'},

    {'id': '\x00\xAB',
     'name': 'DHE_PSK_WITH_AES_256_GCM_SHA384'},

    {'id': '\x00\xAC',
     'name': 'RSA_PSK_WITH_AES_128_GCM_SHA256'},

    {'id': '\x00\xAD',
     'name': 'RSA_PSK_WITH_AES_256_GCM_SHA384'},

    {'id': '\x00\xAE',
     'name': 'PSK_WITH_AES_128_CBC_SHA256'},

    {'id': '\x00\xAF',
     'name': 'PSK_WITH_AES_256_CBC_SHA384'},

    {'id': '\x00\xB0',
     'name': 'PSK_WITH_NULL_SHA256'},

    {'id': '\x00\xB1',
     'name': 'PSK_WITH_NULL_SHA384'},

    {'id': '\x00\xB2',
     'name': 'DHE_PSK_WITH_AES_128_CBC_SHA256'},

    {'id': '\x00\xB3',
     'name': 'DHE_PSK_WITH_AES_256_CBC_SHA384'},

    {'id': '\x00\xB4',
     'name': 'DHE_PSK_WITH_NULL_SHA256'},

    {'id': '\x00\xB5',
     'name': 'DHE_PSK_WITH_NULL_SHA384'},

    {'id': '\x00\xB6',
     'name': 'RSA_PSK_WITH_AES_128_CBC_SHA256'},

    {'id': '\x00\xB7',
     'name': 'RSA_PSK_WITH_AES_256_CBC_SHA384'},

    {'id': '\x00\xB8',
     'name': 'RSA_PSK_WITH_NULL_SHA256'},

    {'id': '\x00\xB9',
     'name': 'RSA_PSK_WITH_NULL_SHA384'},

    {'id': '\x00\xBA',
     'name': 'RSA_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\x00\xBB',
     'name': 'DH_DSS_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\x00\xBC',
     'name': 'DH_RSA_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\x00\xBD',
     'name': 'DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\x00\xBE',
     'name': 'DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\x00\xBF',
     'name': 'DH_anon_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\x00\xC0',
     'name': 'RSA_WITH_CAMELLIA_256_CBC_SHA256'},

    {'id': '\x00\xC1',
     'name': 'DH_DSS_WITH_CAMELLIA_256_CBC_SHA256'},

    {'id': '\x00\xC2',
     'name': 'DH_RSA_WITH_CAMELLIA_256_CBC_SHA256'},

    {'id': '\x00\xC3',
     'name': 'DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256'},

    {'id': '\x00\xC4',
     'name': 'DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256'},

    {'id': '\x00\xC5',
     'name': 'DH_anon_WITH_CAMELLIA_256_CBC_SHA256'},

    # \x00\xC6-FE	Unassigned
    {'id': '\x00\xFF',
     'name': 'EMPTY_RENEGOTIATION_INFO_SCSV'},

    # \x01-BF,*	Unassigned
    {'id': '\xC0\x01',
     'name': 'ECDH_ECDSA_WITH_NULL_SHA'},

    {'id': '\xC0\x02',
     'name': 'ECDH_ECDSA_WITH_RC4_128_SHA'},

    {'id': '\xC0\x03',
     'name': 'ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\xC0\x04',
     'name': 'ECDH_ECDSA_WITH_AES_128_CBC_SHA'},

    {'id': '\xC0\x05',
     'name': 'ECDH_ECDSA_WITH_AES_256_CBC_SHA'},

    {'id': '\xC0\x06',
     'name': 'ECDHE_ECDSA_WITH_NULL_SHA'},

    {'id': '\xC0\x07',
     'name': 'ECDHE_ECDSA_WITH_RC4_128_SHA'},

    {'id': '\xC0\x08',
     'name': 'ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\xC0\x09',
     'name': 'ECDHE_ECDSA_WITH_AES_128_CBC_SHA'},

    {'id': '\xc0\x0A',
     'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
     'authentication': RSA,
     # 'authentication_mode': 	AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 32,
     'block_length': 16,
     'fixed_iv_length': 16,
     'record_iv_length': 16,
     'mac_algorithm': SHA,
     'mac_length': 20,
     'mac_key_length': 20},

    {'id': '\xC0\x0B',
     'name': 'ECDH_RSA_WITH_NULL_SHA'},

    {'id': '\xC0\x0C',
     'name': 'ECDH_RSA_WITH_RC4_128_SHA'},

    {'id': '\xC0\x0D',
     'name': 'ECDH_RSA_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\xC0\x0E',
     'name': 'ECDH_RSA_WITH_AES_128_CBC_SHA'},

    {'id': '\xC0\x0F',
     'name': 'ECDH_RSA_WITH_AES_256_CBC_SHA'},

    {'id': '\xC0\x10',
     'name': 'ECDHE_RSA_WITH_NULL_SHA'},

    {'id': '\xC0\x11',
     'name': 'ECDHE_RSA_WITH_RC4_128_SHA'},

    {'id': '\xC0\x12',
     'name': 'ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\xC0\x13',
     'name': 'ECDHE_RSA_WITH_AES_128_CBC_SHA'},

    {'id': '\xC0\x14',
     'name': 'ECDHE_RSA_WITH_AES_256_CBC_SHA'},

    {'id': '\xC0\x15',
     'name': 'ECDH_anon_WITH_NULL_SHA'},

    {'id': '\xC0\x16',
     'name': 'ECDH_anon_WITH_RC4_128_SHA'},

    {'id': '\xC0\x17',
     'name': 'ECDH_anon_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\xC0\x18',
     'name': 'ECDH_anon_WITH_AES_128_CBC_SHA'},

    {'id': '\xC0\x19',
     'name': 'ECDH_anon_WITH_AES_256_CBC_SHA'},

    {'id': '\xC0\x1A',
     'name': 'SRP_SHA_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\xC0\x1B',
     'name': 'SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\xC0\x1C',
     'name': 'SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\xC0\x1D',
     'name': 'SRP_SHA_WITH_AES_128_CBC_SHA'},

    {'id': '\xC0\x1E',
     'name': 'SRP_SHA_RSA_WITH_AES_128_CBC_SHA'},

    {'id': '\xC0\x1F',
     'name': 'SRP_SHA_DSS_WITH_AES_128_CBC_SHA'},

    {'id': '\xC0\x20',
     'name': 'SRP_SHA_WITH_AES_256_CBC_SHA'},

    {'id': '\xC0\x21',
     'name': 'SRP_SHA_RSA_WITH_AES_256_CBC_SHA'},

    {'id': '\xC0\x22',
     'name': 'SRP_SHA_DSS_WITH_AES_256_CBC_SHA'},

    {'id': '\xC0\x23',
     'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
     'authentication': RSA,
     # 'authentication_mode': 	AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 16,
     'block_length': AES.block_size,
     'fixed_iv_length': AES.block_size,
     'record_iv_length': AES.block_size,
     'mac_algorithm': SHA256,
     'mac_length': SHA256.digest_size,
     'mac_key_length': SHA256.digest_size},

    {'id': '\xC0\x24',
     'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA256',
     'authentication': RSA,
     # 'authentication_mode': 	AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     'cipher_mode': AES.MODE_CBC,
     'enc_key_length': 32,
     'block_length': AES.block_size,
     'fixed_iv_length': AES.block_size,
     'record_iv_length': AES.block_size,
     'mac_algorithm': SHA256,
     'mac_length': SHA256.digest_size,
     'mac_key_length': SHA256.digest_size},

    {'id': '\xC0\x25',
     'name': 'ECDH_ECDSA_WITH_AES_128_CBC_SHA256'},

    {'id': '\xC0\x26',
     'name': 'ECDH_ECDSA_WITH_AES_256_CBC_SHA384'},

    {'id': '\xC0\x27',
     'name': 'ECDHE_RSA_WITH_AES_128_CBC_SHA256'},

    {'id': '\xC0\x28',
     'name': 'ECDHE_RSA_WITH_AES_256_CBC_SHA384'},

    {'id': '\xC0\x29',
     'name': 'ECDH_RSA_WITH_AES_128_CBC_SHA256'},

    {'id': '\xC0\x2A',
     'name': 'ECDH_RSA_WITH_AES_256_CBC_SHA384'},

    {'id': '\xC0\x2B',
     'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
     'authentication': RSA,
     # 'authentication_mode': 	AUTHMODE['RSA'],
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     #  'cipher_mode':		AES.MODE_GCM,
     'enc_key_length': 16,
     'block_length': AES.block_size,
     'fixed_iv_length': AES.block_size,
     'record_iv_length': AES.block_size,
     'mac_algorithm': SHA256,
     'mac_length': SHA256.digest_size,
     'mac_key_length': SHA256.digest_size},

    {'id': '\xC0\x2C',
     'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
     'authentication': RSA,
     'bulk_cipher_algorithm': AES,
     'cipher_type': CIPHERTYPE['BLOCK'],
     #  'cipher_mode':		AES.MODE_GCM,
     'enc_key_length': 32,
     'block_length': AES.block_size,
     'fixed_iv_length': AES.block_size,
     'record_iv_length': AES.block_size,
     'mac_algorithm': SHA384,
     'mac_length': SHA384.digest_size,
     'mac_key_length': SHA384.digest_size},

    {'id': '\xC0\x2D',
     'name': 'ECDH_ECDSA_WITH_AES_128_GCM_SHA256'},

    {'id': '\xC0\x2E',
     'name': 'ECDH_ECDSA_WITH_AES_256_GCM_SHA384'},

    {'id': '\xC0\x2F',
     'name': 'ECDHE_RSA_WITH_AES_128_GCM_SHA256'},

    {'id': '\xC0\x30',
     'name': 'ECDHE_RSA_WITH_AES_256_GCM_SHA384'},

    {'id': '\xC0\x31',
     'name': 'ECDH_RSA_WITH_AES_128_GCM_SHA256'},

    {'id': '\xC0\x32',
     'name': 'ECDH_RSA_WITH_AES_256_GCM_SHA384'},

    {'id': '\xC0\x33',
     'name': 'ECDHE_PSK_WITH_RC4_128_SHA'},

    {'id': '\xC0\x34',
     'name': 'ECDHE_PSK_WITH_3DES_EDE_CBC_SHA'},

    {'id': '\xC0\x35',
     'name': 'ECDHE_PSK_WITH_AES_128_CBC_SHA'},

    {'id': '\xC0\x36',
     'name': 'ECDHE_PSK_WITH_AES_256_CBC_SHA'},

    {'id': '\xC0\x37',
     'name': 'ECDHE_PSK_WITH_AES_128_CBC_SHA256'},

    {'id': '\xC0\x38',
     'name': 'ECDHE_PSK_WITH_AES_256_CBC_SHA384'},

    {'id': '\xC0\x39',
     'name': 'ECDHE_PSK_WITH_NULL_SHA'},

    {'id': '\xC0\x3A',
     'name': 'ECDHE_PSK_WITH_NULL_SHA256'},

    {'id': '\xC0\x3B',
     'name': 'ECDHE_PSK_WITH_NULL_SHA384'},

    {'id': '\xC0\x3C',
     'name': 'RSA_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x3D',
     'name': 'RSA_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x3E',
     'name': 'DH_DSS_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x3F',
     'name': 'DH_DSS_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x40',
     'name': 'DH_RSA_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x41',
     'name': 'DH_RSA_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x42',
     'name': 'DHE_DSS_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x43',
     'name': 'DHE_DSS_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x44',
     'name': 'DHE_RSA_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x45',
     'name': 'DHE_RSA_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x46',
     'name': 'DH_anon_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x47',
     'name': 'DH_anon_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x48',
     'name': 'ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x49',
     'name': 'ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x4A',
     'name': 'ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x4B',
     'name': 'ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x4C',
     'name': 'ECDHE_RSA_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x4D',
     'name': 'ECDHE_RSA_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x4E',
     'name': 'ECDH_RSA_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x4F',
     'name': 'ECDH_RSA_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x50',
     'name': 'RSA_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x51',
     'name': 'RSA_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x52',
     'name': 'DHE_RSA_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x53',
     'name': 'DHE_RSA_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x54',
     'name': 'DH_RSA_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x55',
     'name': 'DH_RSA_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x56',
     'name': 'DHE_DSS_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x57',
     'name': 'DHE_DSS_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x58',
     'name': 'DH_DSS_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x59',
     'name': 'DH_DSS_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x5A',
     'name': 'DH_anon_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x5B',
     'name': 'DH_anon_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x5C',
     'name': 'ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x5D',
     'name': 'ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x5E',
     'name': 'ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x5F',
     'name': 'ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x60',
     'name': 'ECDHE_RSA_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x61',
     'name': 'ECDHE_RSA_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x62',
     'name': 'ECDH_RSA_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x63',
     'name': 'ECDH_RSA_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x64',
     'name': 'PSK_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x65',
     'name': 'PSK_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x66',
     'name': 'DHE_PSK_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x67',
     'name': 'DHE_PSK_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x68',
     'name': 'RSA_PSK_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x69',
     'name': 'RSA_PSK_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x6A',
     'name': 'PSK_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x6B',
     'name': 'PSK_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x6C',
     'name': 'DHE_PSK_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x6D',
     'name': 'DHE_PSK_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x6E',
     'name': 'RSA_PSK_WITH_ARIA_128_GCM_SHA256'},

    {'id': '\xC0\x6F',
     'name': 'RSA_PSK_WITH_ARIA_256_GCM_SHA384'},

    {'id': '\xC0\x70',
     'name': 'ECDHE_PSK_WITH_ARIA_128_CBC_SHA256'},

    {'id': '\xC0\x71',
     'name': 'ECDHE_PSK_WITH_ARIA_256_CBC_SHA384'},

    {'id': '\xC0\x72',
     'name': 'ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\xC0\x73',
     'name': 'ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'},

    {'id': '\xC0\x74',
     'name': 'ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\xC0\x75',
     'name': 'ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'},

    {'id': '\xC0\x76',
     'name': 'ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\xC0\x77',
     'name': 'ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384'},

    {'id': '\xC0\x78',
     'name': 'ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\xC0\x79',
     'name': 'ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384'},

    {'id': '\xC0\x7A',
     'name': 'RSA_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x7B',
     'name': 'RSA_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x7C',
     'name': 'DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x7D',
     'name': 'DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x7E',
     'name': 'DH_RSA_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x7F',
     'name': 'DH_RSA_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x80',
     'name': 'DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x81',
     'name': 'DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x82',
     'name': 'DH_DSS_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x83',
     'name': 'DH_DSS_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x84',
     'name': 'DH_anon_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x85',
     'name': 'DH_anon_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x86',
     'name': 'ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x87',
     'name': 'ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x88',
     'name': 'ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x89',
     'name': 'ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x8A',
     'name': 'ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x8B',
     'name': 'ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x8C',
     'name': 'ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x8D',
     'name': 'ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x8E',
     'name': 'PSK_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x8F',
     'name': 'PSK_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x90',
     'name': 'DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x91',
     'name': 'DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x92',
     'name': 'RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256'},

    {'id': '\xC0\x93',
     'name': 'RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384'},

    {'id': '\xC0\x94',
     'name': 'PSK_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\xC0\x95',
     'name': 'PSK_WITH_CAMELLIA_256_CBC_SHA384'},

    {'id': '\xC0\x96',
     'name': 'DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\xC0\x97',
     'name': 'DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'},

    {'id': '\xC0\x98',
     'name': 'RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\xC0\x99',
     'name': 'RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384'},

    {'id': '\xC0\x9A',
     'name': 'ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'},

    {'id': '\xC0\x9B',
     'name': 'ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'},

    {'id': '\xC0\x9C',
     'name': 'RSA_WITH_AES_128_CCM'},

    {'id': '\xC0\x9D',
     'name': 'RSA_WITH_AES_256_CCM'},

    {'id': '\xC0\x9E',
     'name': 'DHE_RSA_WITH_AES_128_CCM'},

    {'id': '\xC0\x9F',
     'name': 'DHE_RSA_WITH_AES_256_CCM'},

    {'id': '\xC0\xA0',
     'name': 'RSA_WITH_AES_128_CCM_8'},

    {'id': '\xC0\xA1',
     'name': 'RSA_WITH_AES_256_CCM_8'},

    {'id': '\xC0\xA2',
     'name': 'DHE_RSA_WITH_AES_128_CCM_8'},

    {'id': '\xC0\xA3',
     'name': 'DHE_RSA_WITH_AES_256_CCM_8'},

    {'id': '\xC0\xA4',
     'name': 'PSK_WITH_AES_128_CCM'},

    {'id': '\xC0\xA5',
     'name': 'PSK_WITH_AES_256_CCM'},

    {'id': '\xC0\xA6',
     'name': 'DHE_PSK_WITH_AES_128_CCM'},

    {'id': '\xC0\xA7',
     'name': 'DHE_PSK_WITH_AES_256_CCM'},

    {'id': '\xC0\xA8',
     'name': 'PSK_WITH_AES_128_CCM_8'},

    {'id': '\xC0\xA9',
     'name': 'PSK_WITH_AES_256_CCM_8'},

    {'id': '\xC0\xAA',
     'name': 'PSK_DHE_WITH_AES_128_CCM_8'},

    {'id': '\xC0\xAB',
     'name': 'PSK_DHE_WITH_AES_256_CCM_8'},

    # \xC0\xAC-FF	Unassigned
    # \xC1-FD,*	Unassigned
    # \xFE,\x00-FD	Unassigned
    # \xFE,\xFE-FF	Reserved to avoid conflicts with widely deployed implementations		[Pasi_Eronen]
    # \xFF,\x00-FF	Reserved for Private Use		[RFC5246]

    {'id': '\x00\xff',
     'name': 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'}
]
"""

ALERTDESCRIPTION = {0: 'close_notify',
                    10: 'unexpected_message',
                    20: 'bad_record_mac',
                    21: 'decryption_failed_RESERVED',
                    22: 'record_overflow',
                    30: 'decompression_failure',
                    40: 'handshake_failure',
                    41: 'no_certificate_RESERVED',
                    42: 'bad_certificate',
                    43: 'unsupported_certificate',
                    44: 'certificate_revoked',
                    45: 'certificate_expired',
                    46: 'certificate_unknown',
                    47: 'illegal_paramater',
                    48: 'unknown_ca',
                    49: 'access_denied',
                    50: 'decode_error',
                    51: 'decrypt_error',
                    60: 'export_restriction_RESERVED',
                    70: 'protocol_version',
                    71: 'insufficient_security',
                    80: 'internal_error',
                    90: 'user_canceled',
                    100: 'no_renogation',
                    110: 'unsupported_extension'}

ALERTLEVEL = {1: 'warning',
              2: 'fatal'}

EXTENSIONTYPE = {0: 'server_name',
                 1: 'max_fragment_length',
                 2: 'client_certificate_url',
                 3: 'trusted_ca_keys',
                 4: 'truncated_hmac',
                 5: 'status_request',
                 6: 'user_mapping',
                 7: 'client_authz',
                 8: 'server_authz',
                 9: 'cert_type',
                 10: 'elliptic_curves',
                 11: 'ec_point_formats',
                 12: 'srp',
                 13: 'signature_algorithms',
                 14: 'use_srtp',
                 15: 'heartbeat',
                 16: 'application_layer_protocol_negotiation',
                 17: 'status_request_v2',
                 18: 'signed_certificate_timestamp',
                 35: 'SessionTicket TLS',
                 65281: 'renogotiation_info'}

HASHALGORITHM = {0: 'none',
                 1: 'md5',
                 2: 'sha1',
                 3: 'sha224',
                 4: 'sha256',
                 5: 'sha384',
                 6: 'sha512'}

SIGNATUREALGORITHM = {0: 'anonymous',
                      1: 'rsa',
                      2: 'dsa',
                      4: 'ecdsa'}

CLIENT = True
SERVER = False


def long2bstr(value):
    # convert to lttle endian too
    if type(value) == long:
        hstr = hex(value)[2:-1]
    elif type(value) == int:
        hstr = hex(value)[2:]
    else:
        print("unknown type", type(value))
        return "\x00"

    if (len(hstr) % 2 == 1):
        hstr = "0" + hstr

    return hstr.decode('hex')
    # return hstr.decode('hex')[::-1]


def bstr2long(value):
    # convert to lttle endian too
    # value = value[::-1]
    return int(value.encode('hex'), 16)

"""
def ciphersuite(value):
    if type(value) == str:
        value = bstr2long(value)
    for cipher in CIPHER_SUITES:
        if bstr2long(cipher['id']) == value:
            return cipher
    return None


def read_pem_file_to_der(filename):
    pem = open(filename).read()
    lines = pem.replace(" ", '').split()
    der = a2b_base64(''.join(lines[1:-1]))

    return der
    # no diea wha tI am doing


# TODO improve certificate handling code
def decode_cert(incert):
    # print "\r\nincert", incert[:10].encode('hex')
    cert = DerSequence()
    cert.decode(incert)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])

    # subjectPublicKeyInfo = tbsCertificate[5]
    subjectPublicKeyInfo = tbsCertificate[6]

    rsa_key = RSA.importKey(subjectPublicKeyInfo)
    return rsa_key


class DiffieHellman(object):
    prime = 11435638110073884015312138951374632602058080675070521707579703088370446597672067452229024566834732449017970455481029703480957707976441965258194321262569523
    generator = 2

    def __init__(self):
        self.genPrivateKey(64)
        self.genPublicKey()

    def genPrivateKey(self, bytes):
        self.privateKey = bstr2long("\xab" * bytes)

    def genPublicKey(self):
        self.publicKey = pow(self.generator, self.privateKey, self.prime)

    def checkPublicKey(self, otherKey):
        if (otherKey > 2 and otherKey < self.prime - 1):
            return True  # Good enough
        return False

    def genSecret(self, otherKey):
        if (self.checkPublicKey(otherKey) == True):
            sharedSecret = pow(otherKey, self.privateKey, self.prime)
            return sharedSecret
        else:
            raise Exception("Invalid public key.")

    def getKey(self):
        return self.key
"""
