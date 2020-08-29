import freenet.lib.base_proto.tunnel_tcp as tunnel_tcp
import os

builder = tunnel_tcp.builder(tunnel_tcp.MIN_FIXED_HEADER_SIZE)

session_id=os.urandom(16)
data = builder.build_packet(session_id, 1, b"hello,world")

parser = tunnel_tcp.parser(tunnel_tcp.MIN_FIXED_HEADER_SIZE)
parser.input(data)
parser.parse()
parser.parse()
print(parser.get_pkt())
