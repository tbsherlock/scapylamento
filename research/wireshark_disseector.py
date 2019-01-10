"""
Wireshark dissectors are written in C
https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html

#include "config.h"

#include <epan/packet.h>

#define FOO_PORT 1234

static int proto_foo = -1;


void
proto_register_foo(void)
{
    proto_foo = proto_register_protocol (
        "FOO Protocol", /* name       */
        "FOO",      /* short name */
        "foo"       /* abbrev     */
        );
}
"""




"""
Or written in LUA
https://wiki.wireshark.org/Lua/Examples

   1 -- Create a file named by_ip/''ip_addess''.cap with all ip traffic of each ip host. (tshark only?)
   2 -- Dump files are created for both source and destination hosts
   3 function createDir (dirname)
   4     -- this will print out an error if the directory already exists, but that's fine
   5     os.execute("mkdir " .. dirname)
   6 end
   7
   8 local dir = "by_ip"
   9 createDir(dir)
  10
  11 -- create a table to hold the dumper objects/file handles
  12 local dumpers = {}
  13
  14 -- create a listener tap.  By default it creates one for "frame", but we're tapping IP layer.
  15 -- Valid values can be any protocol with tapping support, but to get something useful in the
  16 -- "extractor" argument of the tap's 'packet' function callback (the third argument passed by
  17 -- wireshark into it), it has to be one of the following currently:
  18 -- "actrace", "ansi_a", "ansi_map", "bacapp", "eth", "h225", "http", "ip", "ldap",
  19 -- "smb", "smb2", "tcp", "udp", "wlan", and "frame"
  20 local tap = Listener.new("ip")
  21
  22
  23 -- we will be called once for every IP Header.
  24 -- If there's more than one IP header in a given packet we'll dump the packet once per every header
  25 function tap.packet(pinfo,tvb,ip)
  26     --print("packet called")
  27     local ip_src, ip_dst = tostring(ip.ip_src), tostring(ip.ip_dst)
  28     local src_dmp, dst_dmp
  29
  30     -- get the dumper file handle for this ip addr
  31     src_dmp = dumpers[ip_src]
  32     if not src_dmp then
  33         -- doesn't exist, make a new one, of the same encapsulation type as current file
  34         src_dmp = Dumper.new_for_current( dir .. "/" .. ip_src .. ".pcap" )
  35         dumpers[ip_src] = src_dmp
  36     end
  37
  38     -- dump the current packet as it is (same encap format and content)
  39     src_dmp:dump_current()
  40     src_dmp:flush()
  41
  42     -- now do the same for dest addr
  43     dst_dmp = dumpers[ip_dst]
  44     if not dst_dmp then
  45         dst_dmp = Dumper.new_for_current( dir .. "/" .. ip_dst .. ".pcap" )
  46         dumpers[ip_dst] = dst_dmp
  47     end
  48
  49     dst_dmp:dump_current()
  50     dst_dmp:flush()
  51
  52 end
  53
  54 -- a listener tap's draw function is called every few seconds in the GUI
  55 -- and at end of file (once) in tshark
  56 function tap.draw()
  57     --print("draw called")
  58     for ip_addr,dumper in pairs(dumpers) do
  59              dumper:flush()
  60     end
  61 end
  62
  63 -- a listener tap's reset function is called at the end of a live capture run,
  64 -- when a file is opened, or closed.  Tshark never appears to call it.
  65 function tap.reset()
  66     --print("reset called")
  67     for ip_addr,dumper in pairs(dumpers) do
  68              dumper:close()
  69     end
  70     dumpers = {}
  71 end
"""

