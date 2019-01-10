


def hexdump(data, indent="", bpl=2, addr=False):
    """ Print out large blocks of binary data as in hex format """
    rstr = ""
    for offset in range(0, len(data)):
        if offset % (8*bpl) == 0:
            if addr:
                rstr += "\n" + "%04X:" % offset + indent
            else:
                rstr += "\n" + indent
        if offset % 8 == 0:
            rstr += " "
        rstr += "%02X " % data[offset]
    rstr = "\n" + "".join([s for s in rstr.splitlines(True) if s.strip("\r\n")])
    return rstr

