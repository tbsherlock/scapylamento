



COMP_TYPE = {'COMP_STORED': 0,
             'COMP_SHRUNK': 1,
             'COMP_REDUCED1': 2,
             'COMP_REDUCED2': 3,
             'COMP_REDUCED3': 4,
             'COMP_REDUCED4': 5,
             'COMP_IMPLODED': 6,
             'COMP_TOKEN': 7,
             'COMP_DEFLATE': 8,
             'COMP_DEFLATE64': 9 }


EnumPackChunk, {"name": "compression_type", "default": 0, "enum": COMP_TYPE, "fmt": "B"}




typedef enum <short> {
    COMP_STORED    = 0,
    COMP_SHRUNK    = 1,
    COMP_REDUCED1  = 2,
    COMP_REDUCED2  = 3,
    COMP_REDUCED3  = 4,
    COMP_REDUCED4  = 5,
    COMP_IMPLODED  = 6,
    COMP_TOKEN     = 7,
    COMP_DEFLATE   = 8,
    COMP_DEFLATE64 = 9
} COMPTYPE;




class file_zip(HeterogeneousList):
    """ The header portion of a SSL/TLS packet """
    name = "TLS Packet"
    template = [(ValuePackChunk, {"name": "frSignature", "default": 0x04034b50, "fmt": "4B"}),
                (ValuePackChunk, {"name": "frVersion", "default": 1, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frFlags", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frCompression", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frFileTime", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frFileDate", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frCrc", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frCompressedSize", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frUncompressedSize", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frFileNameLength", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frExtraFieldLength", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frFileName", "default": 0, "fmt": ">H"}),
                (ValuePackChunk, {"name": "frExtraField", "default": 0, "fmt": ">H"}),

                (guesspayload, {})]





// Defines a file record
typedef struct {
    // Header for the file
    char     frSignature[4];    //0x04034b50
    ushort   frVersion;
    ushort   frFlags;
    COMPTYPE frCompression;
    DOSTIME  frFileTime;
    DOSDATE  frFileDate;
    uint     frCrc     <format=hex>;
    uint     frCompressedSize;
    uint     frUncompressedSize;
    ushort   frFileNameLength;
    ushort   frExtraFieldLength;
    if( frFileNameLength > 0 )
        char     frFileName[ frFileNameLength ];
    if( frExtraFieldLength > 0 )
        uchar    frExtraField[ frExtraFieldLength ];

    // Compressed data
    SetBackColor( cNone );
    if( frCompressedSize > 0 )
        uchar    frData[ frCompressedSize ];

} ZIPFILERECORD <read=ReadZIPFILERECORD, write=WriteZIPFILERECORD>;









