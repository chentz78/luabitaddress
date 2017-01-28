local openssl = require'openssl'
local digest = require'openssl'.digest
local pkey = require("openssl").pkey
local bn = require("openssl").bn

local eng = assert(openssl.engine('openssl'))
assert(eng:id(),'openssl')
assert(eng:set_default('RSA'))
assert(eng:set_default('ECDSA'))

local lua_openssl_version, lua_version, openssl_version = openssl.version()
print("Lua ver:        ", lua_version)
print("OpenSSL ver:    ", openssl_version)
print("Lua OpenSSL ver:", lua_openssl_version)


print("Digest check:")
local msg = 'The quick brown fox jumps over the lazy dog.'
print(msg)
print("HEX:", openssl.hex(msg))
print("B64:", openssl.base64(msg))
print("SHA1", digest.digest("sha1",msg))
print("SHA256", digest.digest("sha256",msg))

print("ECKey generation check:")
local ec = pkey.new('ec', 'secp256k1')
local t = ec:parse().ec:parse()
print("EC Priv. Hex:", bn.tohex(t.priv_key))
print("EC Priv. Key:")
print(ec:export())

local k1 = pkey.get_public(ec)
t = k1:parse().ec:parse()
local x,y = t.group:affine_coordinates(t.pub_key)
print("EC Pub. Hex:", bn.tohex(x) .. bn.tohex(y))
print("EC Pub. Key:")
print(k1:export())
