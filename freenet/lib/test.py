import freenet.lib.fn_utils as fn_utils

cls=fn_utils.mbuf()
cls.copy2buf(b"hello")

print(cls.get_part(1))