
import socket
from chunk import TemplateChunk, EnumPackChunk, ValuePackChunk


class IPPackChunk(ValuePackChunk):
    """ Stores an IP address """
    def __init__(self, default, **kwargs):
        super(IPPackChunk, self).__init__(default=default, fmt="4s", **kwargs)

    def human2internal(self, humanval):
        """ Convert human readable value to internal (python stored) value """
        if type(humanval) is str:
            try:
                socket.inet_aton(humanval)
            except socket.error:
                # x = Net(x)  # TODO: define this in a helper function
                raise
        elif type(humanval) is list:
            raise Exception("Cannot convert list to IPChunk")
        self.value = humanval

    def internal2raw(self):
        return socket.inet_aton(self.value)

    def raw2internal(self, rawval):
        print("ipchunk rawval: %s"%(rawval.encode('hex')))
        return socket.inet_ntoa(rawval)

    def internal2human(self):
        return self.value
