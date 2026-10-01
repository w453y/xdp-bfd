# hwts.py IFACE [off]: print the NIC's hwtstamp config; with "off", set rx_filter NONE, tx OFF.
import array, fcntl, socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def call(req, cfg):
    buf = array.array("b", cfg)
    fcntl.ioctl(s, req, struct.pack("16sQ", sys.argv[1].encode(), buf.buffer_info()[0]))
    return struct.unpack("iii", buf.tobytes())
if len(sys.argv) > 2 and sys.argv[2] == "off":
    call(0x89b0, struct.pack("iii", 0, 0, 0))  # SIOCSHWTSTAMP
f, tx, rx = call(0x89b1, struct.pack("iii", 0, 0, 0))  # SIOCGHWTSTAMP
print("tx_type %d rx_filter %d (0 = none, 1 = all)" % (tx, rx))
