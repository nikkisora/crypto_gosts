#%%
import gost_28147_89 as l1
import gost_3411_2012 as l2
import gost_3410_2012 as l3

#%%

r, s = l3.sign('hello world', 5)
vk = l3.get_public_key(5)

print(f'r: \t {hex(r)}')
print(f's: \t {hex(s)}')
print(f'v key x: {hex(vk[0])}')
print(f'v key y: {hex(vk[1])}')
print('verified', l3.verify('hello world', (r, s), vk))

#%%

m1 = int('323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130', 16)

print(f'm1 512 hash:  {l2.gost_hash(m1):#0{130}x}')
print(f'm1 256 hash:  {l2.gost_hash(m1, 256):#0{66}x}')
print('')

m2 = int('fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1', 16)

print(f'm2 512 hash:  {l2.gost_hash(m2):#0{130}x}')
print(f'm2 256 hash:  {l2.gost_hash(m2, 256):#0{66}x}')
print('')

msg = 'hello world'

print(f'msg 512 hash: {l2.gost_hash(msg):#0{130}x}')
print(f'msg 256 hash: {l2.gost_hash(msg, 256):#0{66}x}')
print('')

#%%

text = "hello world of plain text"
key = 1
synchrosignal = 'synchros'

print(f"original text     : {text}")
print('')

#----------ECB---------------

encrypted_text = l1.encrypt_ECB(text, key)

print(f"encrypted text ECB: {encrypted_text}")

decrypted_text = l1.decrypt_ECB(encrypted_text, key)

print(f"decrypted text ECB: {decrypted_text}")
print('')

#----------CTR---------------

encrypted_text = l1.encrypt_CTR(text, key, synchrosignal)

print(f"encrypted text CTR: {encrypted_text}")

decrypted_text = l1.decrypt_CTR(encrypted_text, key, synchrosignal)

print(f"decrypted text CTR: {decrypted_text}")
print('')

#----------CFB---------------

encrypted_text = l1.encrypt_CFB(text, key, synchrosignal)

print(f"encrypted text CFB: {encrypted_text}")

decrypted_text = l1.decrypt_CFB(encrypted_text, key, synchrosignal)

print(f"decrypted text CFB: {decrypted_text}")
print('')

#----------MAC---------------

print('имитовставка для сообщения', hex(l1.generate_MAC(text, key, 4)))
print('проверка имитовставки при изменении сообщения:', l1.generate_MAC(text, key, 4) == l1.generate_MAC(decrypted_text+'a', key, 4))
# %%
