local BTC = {}

local ossl = require("openssl")
local dgst = require("openssl").digest
local b58  = require("base58")
local bn = ossl.bn

local sha256 = function(d) return dgst.digest("sha256", d) end
local ripemd160 = function(d) return dgst.digest("ripemd160", d) end

--Based on https://en.bitcoin.it/wiki/Wallet_import_format
function BTC.genWIF(privKey)
  --print("==>>Private Key:", bn.tohex(privKey), "size:", bn.tohex(privKey):len())
    
  local s = "80"..bn.tohex(privKey)
  local bVal = s
  --print("Step2:", s, "size:", s:len())
  
  s= sha256(ossl.hex(s, false))
  --print("Step3:", s, "size:", s:len())
  
  s= sha256(ossl.hex(s, false))
  --print("Step4:", s, "size:", s:len())
  
  s = s:sub(1,8)
  --print("Step5:", s, "size:", s:len())
  
  s =  ossl.hex(bVal .. s, false)
  --print("Step6:", s, "size:", s:len())
  
  s = b58.enc(s)
  --print("Step7:", s, "size:", s:len())
  return s
end

-- Based on https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
function BTC.genPubAddr(pubKey)
  --print("==>>Pub. Key:", bn.tohex(pubKey))
  local s = "04"..bn.tohex(pubKey)
  s = sha256(ossl.hex(s,false))
  --print("Step2-sha256",s)
  s = ripemd160(ossl.hex(s,false))
  --print("Step3-RIPEMD160",s)
  s = "00"..s
  local RipVer = s
  --print("Step4-Ver",s)
  s = sha256(ossl.hex(s,false))
  --print("Step5-SHA256",s)
  s = sha256(ossl.hex(s,false))
  --print("Step6-SHA256",s)
  crc = s:sub(1,8)
  --print("Step7-CRC",crc)
  s = RipVer..crc
  --print("Step8-Final",s)
  s = b58.enc(ossl.hex(s,false))
  --print("BTC Address",s)
  return s
end

return BTC
