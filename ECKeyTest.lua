local pkey = require("openssl").pkey
local bn = require("openssl").bn

local pkStr = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
local pki=bn.number("X"..pkStr)

print("Orig Private Key HEX:", pkStr)

local ec = pkey.new({alg="ec",ec_name="secp256k1",d=pki})
print("Is Private?", ec:is_private())
local ecPriv = ec:parse().ec:parse().priv_key
print("Priv. HEX:", bn.tohex(ecPriv))

local k1 = pkey.get_public(ec)
t = k1:parse().ec:parse()
local x,y = t.group:affine_coordinates(t.pub_key)
print("Pub. HEX:", bn.tohex(x)..bn.tohex(y))