
import struct
import copy


class Chunk(object):
    """ A chunk of data stuff,
     raw - this is how the chunk is transmitted or stored in its raw byte form
     internal - How the data should be stored in its python format
     human - How this chunk should be manipulated for human interaction """
    name = "unnamed"
    default = None

    def __init__(self, name=None, conditional_fn=None, rawdata=None, default=None, parent=None, *args, **kwargs):
        self.parent = parent  # Parent points back to a chunk containing this chunk, or None if it is a root chunk
        self.value = default  # The value stored in this chunk
        self.conditional_fn = conditional_fn  # this should be a function which returns True if this fiels is present
        if name is not None:
            self.name = name  # A string used to identify this chunk
        if default is not None:
            self.default = default

        if rawdata is not None:
            self.raw2internal(rawdata)

    def __len__(self):
        """ Return the length (in bytes) of this object in raw format """
        return self.internal2length()

    def __repr__(self):
        return self.__class__.__name__ + " - " + str(self.internal2human())

    def human2internal(self, humanval):
        """ Convert human readable value to internal (python stored) value and store it """
        self.value = humanval

    def internal2human(self):
        """ Convert internal (python stored) value to human readable value and return it """
        return str(self.value)

    def raw2internal(self, rawval):
        """Convert raw (on the wire) value to internal (python stored) value and store it """
        return rawval

    def internal2raw(self):
        """Convert internal (python stored) value to raw (on the wire) value and return it """
        return self.value

    def validate_raw(self, rawval):
        """ Takes raw data and determine if this is valid for this chunk type, returns true if it is valid """
        return True

    def raw2length(self, rawval):
        """ return the length (bytes) of this chunk from the raw value """
        return len(rawval)

    def internal2length(self):
        """ return the length (in bytes) in this chunk from the internal value """
        return len(self.value)

    def initialise_from_default(self):
        """ Load default values into the chunk """
        self.value = self.default

    def display_string(self, indent=""):
        return indent + "%s - %s" % (self.name, self.internal2human())


class ValuePackChunk(Chunk):
    """ A chunk which contains a value specified by a struct format string"""
    default = 0

    def __init__(self, fmt, *args, **kwargs):
        self.fmt = fmt  # This is a string containing format characters
        super(ValuePackChunk, self).__init__(*args, **kwargs)

    def internal2raw(self):
        return struct.pack(self.fmt, self.value)

    def raw2internal(self, rawval):
        print("(%s)unpacking %s now.." % (self.name, str(rawval[:6]).encode('hex')))
        self.value = struct.unpack(self.fmt, rawval[:self.raw2length(rawval)])[0]

    def raw2length(self, rawval):
        """ This chunk is always a fixed length """
        return struct.calcsize(self.fmt)

    def internal2length(self):
        """ This chunk is always a fixed length """
        return struct.calcsize(self.fmt)

    def internal2human(self):
        return str(self.value)


class ListChunk(Chunk):
    """ A chunk whereby the internal value is stored as a python list """
    default = []

    def __init__(self, element_type=None, *args, **kwargs):
        self.element_type = element_type  # The default type of chunk
        super(ListChunk, self).__init__(*args, **kwargs)

    def __getitem__(self, key):
        return self.value[key]

    def __setitem__(self, key, value):
        self.value[key] = value

    def __delitem__(self, key):
        self.value.remove(key)

#    def raw2length(self, rawval):
#        raise Exception("Unable to calculate length of list")

    def internal2length(self):
        """ Calculate the length by iterating over all of the elements of the list and  """
        total_size = 0
        for elmnt in self.value:
            total_size += elmnt.internal2length()
        return total_size

    def internal2human(self):
        return "LIST"

    def display_string(self, indent=""):
        rstr = indent + "%s " % self.name + " [ "
        for elmnt in self.value:
            rstr += "\n" + elmnt.display_string(indent + "  ") + ","
        rstr += "  ]"
        return rstr

    def internal2raw(self):
        """ Convert internal (python stored) value to raw (on the wire) value """
        rawdata = ""
        for chunk in self:
            rawdata += chunk.internal2raw()
        return rawdata

    def raw2internal(self, rawdata):
        """ Convert raw value to internal (python stored) value """
        #if self.length_from is None:
        #    raise Exception("Unable to parse raw list, unable to calculate length")
        if self.element_type is None:
            raise Exception("Unable to parse raw list, unknown chunk elements")

        list_length = self.raw2length(rawdata)  # calculate list length in bytes

        self.value = []
        print("unpacking a %s length list (%s).." % (list_length, self.name))
        chunk_type, chunk_args = self.element_type
        remaining_data = rawdata[:list_length]
        while len(remaining_data) > 0:
            print("raw: %s" % (remaining_data[:16].encode('hex')))
            new_chunk = chunk_type(**chunk_args)
            remaining_data = new_chunk.read_from_stream(remaining_data)
            self.value.append(new_chunk)

        return rawdata[list_length:]

    def read_from_stream(self, streamdata):
        datalen = self.raw2length(streamdata)
        print("reading %s bytes" % datalen)
        self.raw2internal(streamdata[:datalen])
        return streamdata[datalen:]


class TemplateChunk(ListChunk):
    """ A chunk which contains a known ordered list of other chunks, the known list of chunks is specified in the template member
    This should contain a list of 2-tuples, of which the first element is a chunk type, and the second element is a dictionary containing arguments to that chunk"""
    template = []
    default = []

    def __init__(self, *args, **kwargs):
        super(TemplateChunk, self).__init__(*args, **kwargs)

    def __getattr__(self, name):
        """ Overload the getattr function, this allows us to access chunks in the list by name"""
        for elmnt in self.value:
            if elmnt.name == name:
                return elmnt
        return super(TemplateChunk, self).__getitem__(name)

    def raw2internal(self, rawval):
        """ Convert raw (on the wire) value to internal (python stored) value """
        rawval_remaining = rawval
        self.value = []

        for chunk_type, chunk_args in self.template:
            chunk_args['parent'] = self
            #chunk_args['rawdata'] = rawval_remaining[:]
            try:
                new_chunk = chunk_type(**chunk_args)
                rawval_remaining = new_chunk.read_from_stream(rawval_remaining)
            except Exception as e:
                print("Failed to initialise a component of templateChunk")
                print("chunk_type: %s chunk_args: %s"%(chunk_type, chunk_args))
                raise
            self.value.append(new_chunk)

        return rawval_remaining


class EnumPackChunk(ValuePackChunk):
    """ This chunk must be from a subset of values.
        acceptable values must be defined in a dictionary, where the key is the
        field and value is a human readable string """
    def __init__(self, enum, *args, **kwargs):
        super(EnumPackChunk, self).__init__(*args, **kwargs)
        self.enum = enum

    def internal2human(self):
        """ Convert internal (python stored) value to human readable value """
        if self.value not in self.enum:
            return "0x" + str(self.value).encode('hex') + " - UNKNOWN"
        return str(self.enum[self.value])

    """
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        if type(enum) is list:
            keys = xrange(len(enum))
        else:
            keys = enum.keys()
        if filter(lambda x: type(x) is str, keys):
            i2s, s2i = s2i, i2s
        for k in keys:
            i2s[k] = enum[k]
            s2i[enum[k]] = k
        Field.__init__(self, name, default, fmt)


    def any2i_one(self, pkt, x):
        if type(x) is str:
            x = self.s2i[x]
        return x

    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x, VolatileValue) and x in self.i2s:
            return self.i2s[x]
        return repr(x)

    def any2i(self, pkt, x):
        if type(x) is list:
            return map(lambda z, pkt=pkt: self.any2i_one(pkt, z), x)
        else:
            return self.any2i_one(pkt, x)

    def i2repr(self, pkt, x):
        if type(x) is list:
            return map(lambda z, pkt=pkt: self.i2repr_one(pkt, z), x)
        else:
            return self.i2repr_one(pkt, x)
    """


class VariableLengthChunk(Chunk):
    """ A chunk which can be various length"""
    def __init__(self, length_from=None, *args, **kwargs):
        self.length_from = length_from  # this should be a function which returns the length of this chunk in bytes
        super(VariableLengthChunk, self).__init__(*args, **kwargs)

    def raw2length(self, rawval):
        """ use the 'length_from' function to calculate the length """
        if self.length_from is None:
            return super(VariableLengthChunk, self).raw2length(rawval)
        return self.length_from(self)


class TerminatedChunk(Chunk):
    """ This is a chunk which is of variable length and also terminated by a specific byte sequence.
        terminate_function: err
    """

    def raw2length(self, rawval):
        """ read through the stream until we detect the sequence """
        while True:
            new_chunk = chunk_type(**chunk_args)
            remaining_data = new_chunk.read_from_stream(remaining_data)
            self.value.append(new_chunk)
            if new_chunk.option_type == 0xff:
                return remaining_data


class LengthOfPackChunk(ValuePackChunk):
    """ This chunk contains data which is calculated"""
    def __init__(self, length_of, *args, **kwargs):
        self.length_of = length_of  # This is a function which returns the value to be stored in this chunk
        super(LengthOfPackChunk, self).__init__(*args, **kwargs)

    def internal2raw(self):
        """ We use the function "length_of" to calculate the value """
        self.value = self.length_of(self)

        return super(LengthOfPackChunk, self).internal2raw()


class X3ByteIntPackChunk(ValuePackChunk):
    """ This field represents a 3 byte long integer, this is a hack to get around the struct module not supporting 3 byte values """
    def __init__(self, *args, **kwargs):
        super(X3ByteIntPackChunk, self).__init__(fmt=">i", *args, **kwargs)

    def internal2raw(self):
        """Convert internal (python stored) value to raw (on the wire) value """
        return struct.pack('>3b', self.value)

    def raw2internal(self, rawval):
        """Convert raw (on the wire) value to internal (python stored) value """
        self.value = struct.unpack(self.fmt, '\x00' + rawval[:3])[0]

    def internal2length(self):
        """ return the length (in bytes) in this chunk from the internal value """
        return 3

    def raw2length(self, rawdata):
        """ return the length (in bytes) in this chunk from the internal value """
        return 3


class BinaryDataChunk(VariableLengthChunk):
    """ A known stream of binary data
        either of the following should be specified:
        length - length of stream in bytes
        length_from - a function which takes a 'BinaryDataChunk' object and returns length """
    def __init__(self, length=None, *args, **kwargs):
        self.length = length
        super(BinaryDataChunk, self).__init__(*args, **kwargs)

    def get_length(self):
        """ Return the length of this object...?"""
        if self.length is not None:
            return self.length
        if self.length_from is not None:
            retval = self.length_from(self)
            if not isinstance(retval, int):
                raise Exception("length_from function did not return an int: %s"%(retval))
            return retval

        raise Exception("unable to calculate length")

    def write_to_stream(self, stream):
        return stream+self.internal2raw()

    def validate_raw(self, rawval):
        """ if the length of rawdata is less than expected length then not valid """
        if len(rawval) < self.get_length():
            return False
        return True

    def internal2human(self):
        """ Convert internal (python stored) value to human readable value """
        return str(self.value).encode('hex')

    def raw2internal(self, rawval):
        """ Convert raw value to internal value"""
        self.value = rawval[:self.get_length()]

    def raw_length(self):
        """ Convert internal value to a length usable by a FieldLenField """
        return self.get_length()

    def read_from_stream(self, streamdata):
        print("XXXX?????",streamdata[:8].encode('hex'), self.get_length())
        print("(%s)unpacking %s now.."%(self.name, str(streamdata[:self.get_length()]).encode('hex')))
        if self.validate_raw(streamdata) is False:
            raise Exception("Failed decoding BinaryDataChunk:%s.(len:%s)" % (streamdata[:16].encode('hex'),self.get_length()))

        self.raw2internal(streamdata)
        return streamdata[self.raw_length():]


class CStringChunk(Chunk):
    """ Null terminated string """
    default = ""

    def __init__(self, *args, **kwargs):
        super(CStringChunk, self).__init__(*args, **kwargs)