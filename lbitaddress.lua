require("init")

local ossl = require("openssl")
local dgst = require("openssl").digest
local pkey = require("openssl").pkey
local b58  = require("base58")
local btc  = require("bitcoin")
local bn = ossl.bn

-- character table string
local sha256 = function(d) return dgst.digest("sha256", d) end
local ripemd160 = function(d) return dgst.digest("ripemd160", d) end
local sha1s = function(d) return dgst.digest("sha1", d):sub(1,7) end --based on git short

local function genECKeyPair()
  local ec = pkey.new('ec', 'secp256k1')
  local t = ec:parse()
  --Checking
  assert(ec:is_private())
  assert(t.size == 72)
  assert(t.type == 'ec')
  assert(t.bits == 256)
  
  t = ec:parse().ec:parse()
  
  --Private Key
  local pki = t.priv_key
  assert(bn.tohex(t.priv_key):len() == 64, "Invalid private key size.")
  
  --print("Priv. Key:", bn.tohex(pki), pki)
  
  local k1 = pkey.get_public(ec)
  --print(k1, type(k1:export()))
  --print(k1:export())
  
  t = k1:parse().ec:parse()
  local x,y = t.group:affine_coordinates(t.pub_key)
  pubkey = bn.number("X" .. bn.tohex(x) .. bn.tohex(y))
  --print("Pub. key:", bn.tohex(pubkey))
  --print("Pub. key (B64):", ossl.base64(bn.totext(pubkey)))
  return pki, pubkey
end

local function getECKeyPub(privK)
  local ec = pkey.new({alg="ec",ec_name="secp256k1",d=privK})
  assert(ec:is_private())
  local k1 = pkey.get_public(ec)
  k1 = k1:parse().ec:parse()
  local x,y = k1.group:affine_coordinates(k1.pub_key)
  return bn.number("X"..bn.tohex(x)..bn.tohex(y))
end

local pki, pubk
local cmd = arg[1]
local extSalt = arg[2]

local regCmds = {
  ['l']=true,
  ['n']=true}
if (not cmd) or 
   (not regCmds[cmd]) then
  print("Options:")
  print("n [salt]","Gen a new BTC address")
  print("l Priv Key Hex","Load BTC address info")
  os.exit(1)
end

if cmd == 'l' then
  if not extSalt or extSalt:len() ~= 64 then
    print("Invalid Priv Key!")
    os.exit(-1)
  end
  print("Loading...")
  pki=bn.number("X"..extSalt)
  pubk=getECKeyPub(pki)
elseif extSalt and extSalt ~= 'n' then
  local locSeed=bn.text(ossl.random(32,true))
  local exSeed =bn.text(extSalt)
  
  print("Using external salt:", extSalt)
  pki=bn.number("X"..sha256(bn.tostring(bn.mul(locSeed, exSeed))))
  pubk=getECKeyPub(pki)
else
  -- Gen ECKey 256
  --
  pki,pubk = genECKeyPair()
  
  --[[Debug
  --WIF
  pki = bn.number("X0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D")
  pubk = bn.number("XD0DE0AAEAEFAD02B8BDC8A01A1B8B11C696BD3D66A2C5F10780D95B7DF42645CD85228A6FB29940E858E7E55842AE2BD115D1ED7CC0E82D934E929C97648CB0A")
 
  
  --PubAddr
  pki = bn.number("X18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")
  pubk = bn.number("X50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6")
  
  PubAddr size: 33
  pki = bn.number("XB9151EEB78539685A1C5494A3F7A02331359B83EEFAD035AA3E6166C7B151B29")
  pubk=getECKeyPub(pki)
  ]]
end

print("==>>Using the Keys:")
local s = bn.tohex(pki)
print("Priv Key Hex:", s, "                                                                SHA1 Head", sha1s(s), "Size:", s:len())
s = ossl.base64(bn.totext(pki))
print("Priv Key B64:", s, "                                                                                        SHA1 Head", sha1s(s), "Size:", s:len())
s = bn.tohex(pubk)
print("Pub Key Hex:", s,  "SHA1 Head", sha1s(s), "Size:", s:len())
print("==>>BTC Info:")
local wif = btc.genWIF(pki)
local pubAdd = btc.genPubAddr(pubk)

print("WIF Format:", wif, "SHA1 Head", sha1s(wif), "Size:", wif:len())
assert(wif:sub(1,1) == '5')
assert(wif:len() == 51)
print("BTC Address:", pubAdd, "                SHA1 Head", sha1s(pubAdd), "Size:", pubAdd:len())
assert(pubAdd:sub(1,1) == '1')
assert(pubAdd:len() == 33 or pubAdd:len() == 34)

--[[The diff between totext() and tostring()
n16 = bn.number(16)
print(n16, bn.totext(n16), bn.tostring(n16))
print(ossl.hex("3136",false))
]]