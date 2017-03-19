import freenet.lib.fn_utils as fn_utils

cls=fn_utils.mbuf()
cls.copy2buf(b"hello")

cls.offset+=2
print(cls.get_part(1))