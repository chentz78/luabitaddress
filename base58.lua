local B58 = {}

local ossl = require("openssl")
local bn = require("openssl").bn

--from https://github.com/leafo/lua-base58/blob/master/base58/init.lua
local alphabet =
"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

function B58.enc(val)
  local bi = bn.text(val)
  local alphLen = alphabet:len()
  
  --print("B58.enc", bi, bn.tohex(bi), alphabet, alphLen )
  local buffer = { }
  local int = bi
  local r,idx
  local ch
  while not bn.iszero(int) do
    int, r = bn.divmod(int, alphLen)
    idx = bn.tonumber(r)+1
    ch = alphabet:sub(idx,idx)
    --print("B58.enc", int, r, ch)
    buffer[#buffer+1] = ch
  end
  
  for i=1,#val do
    if val:byte(i) == 0 then buffer[#buffer+1] = alphabet:sub(1,1) 
    else break end
  end
  
  return table.concat(buffer):reverse()
end

function B58.dec(str)
  local alphLen = alphabet:len()
  local out = bn.number(0)
  
  local lZeros = 0
  print("B58.dec", str:len(), alphabet, alphLen)
  for i=1,str:len() do
    if str:sub(i,i) ~= "1" then break end
    lZeros = lZeros + 1
  end
  
  for i=1, #str do
    local char = str:sub(i, i)
    local char_i = alphabet:find(char)
    if not (char_i) then error("Invalid input string!") end
    local powerOf = (#str-i)+1
    print(i, char, char_i, powerOf, out)
    out = bn.add(out, bn.mul(char_i, bn.pow(alphLen, powerOf)))
    --out = bn.add(bn.mul(out, alphLen), char_byte)
    --out:add(char_byte)
  end
  print("B58.dec, result", out, bn.totext(out):len())
  print("B58.dec, result", bn.tohex(out))
  return out
end

--[[Test to debug dec()
local sd = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
print("checking encode dgst:", dgst.digest("md5",r), dgst.digest("md5",r) == dgst.digest("md5",sd))
print("==>>Decode code:", sd, "size:", sd:len())
print("BTCB58_dec", BTCB58_dec(sd))
print("b58.decode", bn.number(b58.decode(sd)))
print(bn.pow(58,1))
]]

return B58