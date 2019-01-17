import struct
import copy
import binascii
import os
from helper import hexdump


class NULL(object):
    """ An empty object (rather that None, which is for uninitialised) """
    pass


class Chunk(object):
    """ A chunk of data stuff,
     raw - this is how the chunk is transmitted or stored in its raw form; must be a byte string
     internal - How the data should be stored in its python representation
     human - How this chunk should be displayed for human interaction; must be a string """
    name = "unnamed"
    default = ""

    def __init__(self, name=None, default=None, raw_value=None, human_value=None, internal_value=None, parent=None, *args, **kwargs):
        self.parent = parent  # Parent points back to a chunk containing this chunk, or None if it is a root chunk
        self.internal_value = self.default  # The value stored in this chunk
        if name is not None:
            self.name = name  # A string used to identify this chunk
        if raw_value is not None:
            assert isinstance(raw_value, bytes), "raw_value must be of type 'bytes'; %s" % type(raw_value)
            self.internal_value = self.raw2internal(raw_value)
        elif human_value is not None:
            assert isinstance(human_value, str), "human_value must be of type 'str'; %s" % type(human_value)
            self.internal_value = self.human2internal(human_value)
        elif internal_value is not None:
            self.internal_value = internal_value
        else:
            self.initialise_from_default(default)

    def initialise_from_default(self, some_value):
        """ Load default values into the chunk """
        self.internal_value = some_value

    #def __repr__(self):
    #    return self.__class__.__name__ + " - " + str(self.human_value)

    def display_string(self, indent=""):
        return indent + "%s - %s" % (self.name, self.human_value)

    @property
    def human_value(self):
        """ Return this chunk as its human readable value """
        if self.internal_value is None:
            raise Exception("Cannot interpret as human: internal value not set")
        return self.internal2human(self.internal_value)

    @human_value.setter
    def human_value(self, human_value):
        """ Set the chunk by its human readable value """
        assert isinstance(human_value, str), "human_value must be instance of 'str'; %s" % type(human_value)
        self.internal_value = self.human2internal(human_value)

    @property
    def raw_value(self):
        """ Return this chunk as its raw value """
        if self.internal_value is None:
            raise Exception("Cannot interpret as raw: internal value not set")
        return self.internal2raw(self.internal_value)

    @raw_value.setter
    def raw_value(self, raw_value):
        """ Set the internal value by parsing raw value """
        assert isinstance(raw_value, bytes), "raw_value must be instance of 'bytes'; %s" % type(raw_value)
        self.internal_value = self.raw2internal(raw_value)

    @property
    def raw_length(self):
        """ return the raw length (in octets) of this chunk """
        return self.internal2rawlength(self.internal_value)

    """ These should be implemented by sub-classes """
    def raw2internal(self, raw_value):
        """ Convert raw value to internal value and return it """
        return raw_value

    def internal2raw(self, internal_value):
        """ Convert internal value to raw value and return it """
        return self.internal_value

    def internal2rawlength(self, internal_value):
        """ return the length (in octets) of this chunk from its internal format value """
        return len(internal_value)

    def human2internal(self, human_value):
        """ Convert human value to internal value and set return it """
        return human_value

    def internal2human(self, internal_value):
        """ Convert human readable value to internal value and return it """
        return str(internal_value)

    def validate_raw(self, raw_value):
        """ Takes raw data and determine if this is valid for this chunk type, returns true if it is valid """
        return True

    def read_from_stream(self, stream_data):
        """ reads this chunk from a stream of data, return internal value, and any unconsumed stream """
        chunk_len = self.raw_length
        raw_data = stream_data[:chunk_len]
        internal_value = self.raw2internal(raw_data)
        remaining_data = stream_data[chunk_len:]
        return internal_value, remaining_data


class OctetStringChunk(Chunk):
    """ An Octet string is a series of  Chunk which is always the same length in raw form """
    def __init__(self, *args, **kwargs):
        """ raw_length is the length in octets of the raw data chunk """
        super(OctetStringChunk, self).__init__(*args, **kwargs)

    def display_string(self, indent=""):
        rstr = ""
        rstr += indent + "%s - " % self.name
        rstr += hexdump(self.internal_value, indent+"  ")
        return rstr

    def initialise_from_default(self, some_value):
        self.internal_value = b"\x11" * self.raw_length

    def raw2internal(self, raw_value):
        """ both raw and internal value are bytes """
        assert isinstance(raw_value, bytes), "raw_value must be of type 'bytes'; %s" % type(raw_value)
        return raw_value

    def internal2raw(self, internal_value):
        """ both raw and internal value are bytes """
        assert isinstance(internal_value, bytes), "internal_value must be of type 'bytes'; %s" % type(internal_value)
        return internal_value

    def internal2rawlength(self, internal_value):
        """ raw length is hard-coded within the raw_length_value """
        #assert isinstance(internal_value, bytes), "internal_value must be of type 'bytes'; %s" % type(internal_value)
        return len(self.internal_value)

    def internal2human(self, internal_value):
        """ internal value is a byte string, convert it to a hex string for human consumption """
        return binascii.hexlify(internal_value).decode('utf-8')

    def human2internal(self, human_value):
        """ human value is a hex character string, convert it to a byte string for internal """
        return binascii.unhexlify(human_value)

    @property
    def raw_length(self):
        """ return the raw length (in octets) of this chunk """
        return self.internal2rawlength(self.internal_value)


class ASCIIEncodedDecimal(OctetStringChunk):
    """ This is a decimal (unsigned integer ish) number with a fixed number of digits, where each digit is represented
    as a single utf=8 decimal character, and left justified with ascii zeroes up to the length """

    def display_string(self, indent=""):
        rstr = ""
        rstr += indent + "%s - %s" % (self.name, self.human_value)
        return rstr

    def raw2internal(self, raw_value):
        """ raw value is a byte string, internal value is an unsigned integer """
        assert isinstance(raw_value, bytes), "raw_value must be of type 'bytes'; %s" % type(raw_value)
        return int(raw_value)

    def internal2raw(self, internal_value):
        """ internally stored as an integer, convert to utf-8 and pad with 0x30s """
        assert isinstance(internal_value, int), "raw_value must be of type 'int'; %s" % type(internal_value)
        bstr = bytes(str(internal_value), 'utf-8')
        return (b"\x30" * (self.raw_length - len(bstr))) + bstr

    def human2internal(self, human_value):
        """ human value and internal value are the same """
        assert int(human_value) >= 0, "human_value must be positive; %s" % human_value
        return int(human_value)

    def internal2human(self, internal_value):
        """ Convert human readable value to internal value and return it """
        return str(internal_value)

    def internal2rawlength(self, internal_value):
        return len(self.human_value)

    def validate_raw(self, raw_value):
        """ Takes raw data and determine if this is valid for this chunk type, returns true if it is valid """
        return True


class StaticLengthChunk(Chunk):
    """ A Chunk which is always the same length in raw form """
    def __init__(self, raw_length, *args, **kwargs):
        self.raw_length_value = raw_length
        super(StaticLengthChunk, self).__init__(*args, **kwargs)

    def internal2rawlength(self, internal_value):
        """ return the length (in bytes) in this chunk from the internal value """
        return self.raw_length_value

    def internal2human(self, internal_value):
        """ Convert human readable value to internal (python stored) value and return it """
        return binascii.hexlify(internal_value)


class ValuePackChunk(StaticLengthChunk):
    """ A chunk which contains a value specified by a struct format string"""
    default = 0

    def __init__(self, fmt, *args, **kwargs):
        self.fmt = fmt  # This is a string containing format characters
        raw_length = struct.calcsize(self.fmt)
        super(ValuePackChunk, self).__init__(raw_length, *args, **kwargs)

    def internal2raw(self, internal_value):
        return struct.pack(self.fmt, internal_value)

    def raw2internal(self, raw_value):
        return struct.unpack(self.fmt, raw_value[:self.raw_length])[0]

    def internal2rawlength(self, internal_value):
        """ This chunk is always a fixed length, and we can calculate from the fmt string """
        return struct.calcsize(self.fmt)

    def internal2human(self, internal_value):
        return str(self.internal_value)

    def human2internal(self, human_value):
        return int(human_value)


class CharChunk(ValuePackChunk):
    def __init__(self, *args, **kwargs):
        super(CharChunk, self).__init__(fmt="c", *args, **kwargs)


class ShortChunk(ValuePackChunk):
    def __init__(self, *args, **kwargs):
        super(ShortChunk, self).__init__("h", *args, **kwargs)


class UShortChunk(ValuePackChunk):
    def __init__(self, *args, **kwargs):
        super(UShortChunk, self).__init__("H", *args, **kwargs)


class LongChunk(ValuePackChunk):
    def __init__(self, *args, **kwargs):
        super(LongChunk, self).__init__("l", *args, **kwargs)


class ULongChunk(ValuePackChunk):
    def __init__(self, *args, **kwargs):
        super(ULongChunk, self).__init__(">L", *args, **kwargs)


class FloatChunk(ValuePackChunk):
    def __init__(self, *args, **kwargs):
        super(FloatChunk, self).__init__("f", *args, **kwargs)

    def human2internal(self, human_value):
        return float(human_value)


class EnumDataChunk(OctetStringChunk):
    """ This chunk must be from a subset of values.
        acceptable values must be defined in a dictionary, where the key is the
        field and value is a human readable string """
    def __init__(self, enum, *args, **kwargs):
        super(EnumDataChunk, self).__init__(*args, **kwargs)
        self.enum = enum

    def display_string(self, indent=""):
        rstr = ""
        rstr += indent + "%s - %s" % (self.name, self.human_value)
        return rstr

    def internal2human(self, internal_value):
        """ Convert internal (python stored) value to human readable value """
        if internal_value not in self.enum:
            return "0x" + binascii.hexlify(internal_value) + " - UNKNOWN"
        return str(self.enum[self.internal_value])

    def human2internal(self, human_value):
        reverse_lookup = {v: k for k, v in self.enum.items()}
        return reverse_lookup[human_value]


class EnumPackChunk(ValuePackChunk):
    """ This chunk must be from a subset of values.
        acceptable values must be defined in a dictionary, where the key is the
        field and value is a human readable string """
    def __init__(self, enum, *args, **kwargs):
        super(EnumPackChunk, self).__init__(*args, **kwargs)
        self.enum = enum

    def display_string(self, indent=""):
        rstr = ""
        rstr += indent + "%s - %s" % (self.name, self.human_value)
        return rstr

    def internal2human(self, internal_value):
        """ Convert internal (python stored) value to human readable value """
        if self.internal_value not in self.enum:
            return "0x" + str(internal_value).encode('hex') + " - UNKNOWN"
        return str(self.enum[self.internal_value])

    def human2internal(self, human_value):
        reverse_lookup = {v: k for k, v in self.enum.items()}
        return reverse_lookup[human_value]


class X3ByteIntPackChunk(OctetStringChunk):
    """ This field represents a 3 byte long integer, this is a hack to get around the struct module not supporting 3 byte values """
    def __init__(self, *args, **kwargs):
        super(X3ByteIntPackChunk, self).__init__(raw_length=3, *args, **kwargs)

    def display_string(self, indent=""):
        return indent + "%s - %s" % (self.name, self.human_value)

    def internal2raw(self, internal_value):
        """Convert internal (python stored) value to raw (on the wire) value """
        return struct.pack('>I', internal_value)[1:]

    def raw2internal(self, raw_value):
        """Convert raw (on the wire) value to internal (python stored) value """
        return struct.unpack('>I', b'\x00' + raw_value)[0]

    def internal2rawlength(self, internal_value):
        """ return the length (in bytes) in this chunk from the internal value """
        return 3

    def raw2length(self, raw_data):
        """ return the length (in bytes) in this chunk from the internal value """
        return 3

    def internal2human(self, internal_value):
        """ internal value is a byte string, convert it to a hex string for human consumption """
        return str(internal_value)

    def human2internal(self, human_value):
        """ human value is a hex character string, convert it to a byte string for internal """
        return int(human_value, 10)


class CStringChunk(Chunk):
    """ Null terminated string, read bytes until terminator string """
    default = ""

    def __init__(self, *args, **kwargs):
        super(CStringChunk, self).__init__(*args, **kwargs)
        internal_value, remaining_data = self.read_from_stream(kwargs['raw_value'])
        self.internal_value = internal_value

    #def internal2rawlength(self, internal_value):
    #    """ The length of the string + the 1 byte null terminator """
    #    return len(internal_value) + 1

    def raw2internal(self, raw_value):
        """ Convert raw value to internal value and return it """
        return raw_value[:-1]

    def internal2raw(self, internal_value):
        """ Convert internal value to raw value and return it """
        return self.internal_value + b"\x00"

    def internal2rawlength(self, internal_value):
        """ return the length (in octets) of this chunk from its internal format value """
        return len(internal_value) + 1

    def human2internal(self, human_value):
        """ Convert human value to internal value and set return it """
        return human_value.encode('utf-8')

    def internal2human(self, internal_value):
        """ Convert human readable value to internal value and return it """
        return internal_value.decode('utf-8')

    def validate_raw(self, raw_value):
        """ Takes raw data and determine if this is valid for this chunk type, returns true if it is valid """
        return True

    def read_from_stream(self, stream_data):
        for i in range(0, len(stream_data)):
            if stream_data[i] in b"\x00":
                internal_value = stream_data[:i]
                remaining_data = stream_data[i+1:]
                return internal_value, remaining_data

        raise Exception("Reached end of stream, but found no null terminator")


class DictChunk(Chunk):
    """ A chunk whereby the internal value is stored as a python list """
    default = {}

    def __init__(self, *args, **kwargs):
        super(DictChunk, self).__init__(*args, **kwargs)

    def __getitem__(self, key):
        return self.internal_value[key]

    def __getattr__(self, name):
        """ Overload the getattr function, this allows us to access chunks in the list by name """
        return self.internal_value[name]

    def __setitem__(self, key, value):
        self.internal_value[key] = value

    def __delitem__(self, key):
        self.internal_value.remove(key)

    def raw2internal(self, raw_value):
        raise Exception("Base implementation of ListChunk does not support raw2internal")

    def internal2raw(self, internal_value):
        """ Convert internal (python stored) value to raw (on the wire) value and return it """
        raw_data = b""
        for chunk in internal_value:
            raw_data += chunk.raw_value
        return raw_data

    def internal2rawlength(self, internal_value):
        """ Calculate the length by iterating over all of the elements of the list and  """
        total_size = 0
        for elmnt in internal_value:
            total_size += elmnt.raw_length
        return total_size

    def human2internal(self, human_value):
        raise Exception("Base implementation of ListChunk does not support human2internal")

    def internal2human(self, internal_value):
        rstr = "%s " % self.name + " { "
        for elmnt in internal_value.keys():
            rstr += elmnt + self.internal_value[elmnt].human_value + ","
        rstr += " ]"
        return rstr

    def display_string(self, indent=""):
        rstr = indent + "%s " % self.name + " [ "
        for elmnt in self.internal_value:
            rstr += "\n" + elmnt.display_string(indent + "  ") + ","
        rstr += "  ]"
        return rstr


class ListChunk(Chunk):
    """ A chunk whereby the internal value is stored as a python list """
    default = []

    def __init__(self, *args, **kwargs):
        super(ListChunk, self).__init__(*args, **kwargs)

    def raw2internal(self, raw_value):
        raise Exception("Base implementation of ListChunk does not support raw2internal")

    def internal2raw(self, internal_value):
        """ Convert internal (python stored) value to raw (on the wire) value and return it """
        assert isinstance(internal_value, list), "Internal value of ListChunk must be type 'list'; %s" % type(internal_value)
        rstr = b""
        for chunk in internal_value:
            rstr += chunk.raw_value
        return rstr

    def internal2rawlength(self, internal_value):
        """ Calculate the length by iterating over all of the elements of the list and calculating their length """
        assert isinstance(internal_value, list), "Internal value of ListChunk must be type 'list'; %s" % type(internal_value)
        total_size = 0
        for chunk in internal_value:
            total_size += chunk.raw_length
        return total_size

    def human2internal(self, human_value):
        """ This is not implemented here because the format of the element is not defined. """
        raise Exception("Base implementation of ListChunk does not support human2internal")

    def internal2human(self, internal_value):
        """ A basic implimentation is defined here, this is probably not sufficient for general use """
        rstr = "%s " % self.name + "["
        for elmnt in internal_value:
            rstr += elmnt.human_value + ","
        rstr += "]"
        return rstr

    def display_string(self, indent=""):
        rstr = indent + "%s " % self.name + " [ "
        sep = ""
        for elmnt in self.internal_value:
            rstr += "\n" + elmnt.display_string(indent + "  ") + sep
            sep = ","
        rstr += " ]"
        return rstr

    '''
    def raw2internal(self, raw_data):
        """ Convert raw value to internal (python stored) value """
        #if self.length_from is None:
        #    raise Exception("Unable to parse raw list, unable to calculate length")
        if self.element_type is None:
            raise Exception("Unable to parse raw list, unknown list elements")

        self.internal_value = []
        chunk_type, chunk_args = self.element_type

        # Calculate the number of elements in this list
        test_chunk = chunk_type(**chunk_args)
        list_length = self.raw2length(raw_data)  # calculate list length in bytes
        element_len = test_chunk.raw2length(raw_data)
        element_count = list_length / element_len
        print("(%s) Unpacking a %s element list .." % (self.name, element_count))

        for i in range(0,element_count):
            new_chunk = chunk_type(**chunk_args)
            new_chunk.raw2internal(raw_data[i*element_len:(i+1)*element_len])
            self.internal_value.append(new_chunk)

    def read_from_stream(self, streamdata):
        datalen = self.raw2length(streamdata)
        print("reading %s bytes" % datalen)
        self.raw2internal(streamdata[:datalen])
        return streamdata[datalen:]
    '''


class StaticListChunk(ListChunk, StaticLengthChunk):
    """ A List chunk (contains other chunks), where the List is always of a known length """
    def __init__(self, element_type, *args, **kwargs):
        self.element_type = element_type
        super(StaticListChunk, self).__init__(*args, **kwargs)

    def raw2internal(self, raw_data):
        """ Convert raw value to internal (python stored) value """
        self.internal_value = []
        chunk_type, chunk_args = self.element_type

        # Calculate the number of elements in this list
        test_chunk = chunk_type(**chunk_args)
        list_length = self.raw_length  # calculate list length in bytes
        element_len = test_chunk.get_raw_length()  # calculate length of one element
        element_count = list_length / element_len  # calculate number of elements
        print("(%s) Unpacking a %s element list .." % (self.name, element_count))

        for i in range(0, element_count):
            new_chunk = chunk_type(**chunk_args)
            new_chunk.raw2internal(raw_data[i*element_len:(i+1)*element_len])
            self.internal_value.append(new_chunk)


class HomogeneousList(ListChunk):
    """ A List chunk (contains other chunks), where the elements are the same type """
    def __init__(self, element_type, element_count, *args, **kwargs):
        self.element_type = element_type
        self.element_count = element_count  # This should be a function that returns the number of elements
        super(HomogeneousList, self).__init__(*args, **kwargs)

    def raw2internal(self, raw_data):
        """ Convert raw value to internal (python stored) value """
        chunk_type, chunk_args = self.element_type
        chunk_args['parent'] = self
        internal_value = []

        test_chunk = chunk_type(**chunk_args)
        element_len_bytes = test_chunk.raw_length  # calculate length of one element in bytes

        for elmnt in range(0, self.element_count(self)):
            new_chunk = chunk_type(**chunk_args)
            new_chunk.raw_value = raw_data[elmnt * element_len_bytes:(elmnt + 1) * element_len_bytes]
            internal_value.append(new_chunk)

        return internal_value

        """
        ####  This code is from a scenario where we do not know the number of elements.
        self.internal_value = []
        chunk_type, chunk_args = self.element_type

        # Calculate the number of elements in this list
        test_chunk = chunk_type(**chunk_args)
        list_length = self.internal2length(self.internal_value)  # calculate list length in bytes
        element_len = test_chunk.get_raw_length()  # calculate length of one element
        element_count = list_length / element_len  # calculate number of elements
        print("(%s) Unpacking a %s element list .." % (self.name, element_count))

        for i in range(0, element_count):
            new_chunk = chunk_type(**chunk_args)
            new_chunk.raw2internal(raw_data[i * element_len:(i + 1) * element_len])
            self.internal_value.append(new_chunk)
        """

    def read_from_stream(self, stream_data):
        chunk_type, chunk_args = self.element_type
        internal_value = []

        test_chunk = chunk_type(**chunk_args)
        element_len = test_chunk.raw_length  # calculate length of one element
        list_length = self.internal2rawlength(self.internal_value)  # calculate list length in bytes
        remaining_data = stream_data

        print("element count was: %s" % self.element_count(self))
        for elmnt in range(0, self.element_count(self)):
            new_chunk = chunk_type(**chunk_args)
            internal_value.append(new_chunk)
            remaining_data = new_chunk.read_from_stream(remaining_data)
            print("done appended new chunk: %s" % new_chunk)

        return internal_value, remaining_data

#class StaticTemplateChunk(TemplateChunk, StaticLengthChunk)
#    """ A List chunk (contains other chunks), where the List is always of a known length """
#    pass


#class VarListChunk(ListChunk, VariableLengthChunk):
#    """ A List chunk (contains other chunks), where the length is calculated from another field """
#    def __init__(self, *args, **kwargs):
#        super(VarListChunk, self).__init__(*args, **kwargs)


class HeterogeneousList(ListChunk):
    """ A chunk which contains a known ordered list of other chunks, the known list of chunks is specified in the template member
    This should contain a list of 2-tuples, of which the first element is a chunk type, and the second element is a dictionary containing arguments to that chunk"""
    template = []

    def __init__(self, *args, **kwargs):
        super(HeterogeneousList, self).__init__(*args, **kwargs)

    def raw2internal(self, raw_value):
        self.internal_value = []
        rawval_remaining = raw_value

        for chunk_type, chunk_args in self.template:
            chunk_args['parent'] = self
            #chunk_args['raw_data'] = rawval_remaining[:]
            try:
                new_chunk = chunk_type(**chunk_args)
                self.internal_value.append(new_chunk)
                internal_value, rawval_remaining = new_chunk.read_from_stream(rawval_remaining)
                new_chunk.internal_value = internal_value
            except Exception as e:
                print("Failed to initialise a component of templateChunk")
                print("chunk_type: %s chunk_args: %s" % (chunk_type, chunk_args))
                raise

    def read_from_stream(self, stream_data):
        rawval_remaining = stream_data
        self.internal_value = []

        for chunk_type, chunk_args in self.template:
            chunk_args['parent'] = self
            #chunk_args['raw_data'] = rawval_remaining[:]
            try:
                new_chunk = chunk_type(**chunk_args)
                self.internal_value.append(new_chunk)
                internal_value, rawval_remaining = new_chunk.read_from_stream(rawval_remaining)
                new_chunk.internal_value = internal_value
            except Exception as e:
                print("Failed to initialise a component of templateChunk")
                print("chunk_type: %s chunk_args: %s"%(chunk_type, chunk_args))
                raise

        return rawval_remaining
