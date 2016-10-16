from chunk import *


class StreamChunk(Chunk):
    def __init__(self, *args, **kwargs):
        super(StreamChunk, self).__init__(*args, **kwargs)

    def write_to_stream(self, stream):
        """ Add an internal value to a stream"""
        return stream + self.internal2raw()

    def read_from_stream(self, stream):
        """ Extract an internal value from a stream, return the remaining unconsumed stream """
        if self.validate_raw(stream) is False:
            raise Exception("cannot read from stream: %s, invalid for type %s" % (str(stream[0:16]), self))

        rawlen = self.raw2length(stream)
        rawdata = stream[:rawlen]
        print("rawlen  %s rawdata %s" % (rawlen, rawdata.encode('hex')))
        self.raw2internal(rawdata)

        return stream[rawlen:]


class StreamValuePackChunk(ValuePackChunk, StreamChunk):
    pass


class StreamListChunk(ListChunk, StreamChunk):
    pass


class StreamTemplateChunk(TemplateChunk, StreamChunk):
    pass


class StreamEnumPackChunk(EnumPackChunk, StreamChunk):
    pass



