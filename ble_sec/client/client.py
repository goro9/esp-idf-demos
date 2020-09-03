import time
import datetime
import ed25519

ut = time.time()
rut = round(ut)
print(rut)
rut_bytes = rut.to_bytes(8, byteorder='little')
print(rut_bytes)
rut = int.from_bytes(rut_bytes, byteorder='little')
print(rut)
dt = datetime.datetime.fromtimestamp(rut)
print(dt)

sk, pk = ed25519.create_keypair()
print(sk.to_ascii(encoding='hex'))
print(pk.to_ascii(encoding='hex'))

msg = rut_bytes
signature = sk.sign(msg, encoding='hex')
print('signature', signature)

try:
    pk.verify(signature, msg, encoding='hex')
    print('ok')
except:
    print('ng')