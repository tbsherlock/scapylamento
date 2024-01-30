
import socket
from chunk import HeterogeneousList, EnumPackChunk, ValuePackChunk


class IPPackChunk(ValuePackChunk):
    """ Stores an IP address """
    def __init__(self, default, **kwargs):
        super(IPPackChunk, self).__init__(default=default, fmt="4s", **kwargs)

    def human2internal(self, human_value):
        """ Convert human readable value to internal (python stored) value """
        if type(human_value) is str:
            try:
                socket.inet_aton(human_value)
            except socket.error:
                # x = Net(x)  # TODO: define this in a helper function
                raise
        elif type(human_value) is list:
            raise Exception("Cannot convert list to IPChunk")
        self.value = human_value

    def internal2raw(self):
        return socket.inet_aton(self.value)

    def raw2internal(self, raw_value):
        print("ipchunk rawval: %s" % (raw_value.hex()))
        return socket.inet_ntoa(raw_value)

    def internal2human(self):
        return self.value
