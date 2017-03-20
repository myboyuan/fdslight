import dns.message

try:
    dns.message.from_wire(b"ssssssssssssssssss")
except:
    print("hello")