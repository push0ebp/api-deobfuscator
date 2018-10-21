
function disas(addr)
  local disassStr = disassemble(addr)
  local extraField, opcode, bytes, address = splitDisassembledString(disassStr)
  return address, opcode
end

function getDestAddr(addr, jmp)
  local address, opcode = disas(addr)
  local destAddr = nil
  if (jmp and string.match(opcode, '^j%a+%s+')) or
    string.find(opcode, "call") then
    local addr = string.match(opcode, '%s+%[?(%x+)%]?$')
    if addr then
      destAddr = tonumber(addr, 16)
      if string.find(opcode, 'word ptr') then
         destAddr = readPointer(addr)
      end
    end
  end
  return destAddr
end


function follows(addr)
  local CNT = 0x300
  local pc = addr
  for i = 0, CNT do
    local destAddr = getDestAddr(pc, true)
    if destAddr then
      pc = destAddr
    else
      pc = pc + getInstructionSize(pc)
    end
    if inSystemModule(pc) then
      return pc
    end
  end
  return nil
end

function getApiAddr(addr)
  local apiAddr = follows(addr)
  if apiAddr then
    apiAddr = getNameFromAddress(apiAddr)
    apiAddr = string.gsub(apiAddr, '%+(%x+)$', "")
    apiAddr = getAddress(apiAddr)
    return apiAddr
  end
  return nil
end

function fix_api(addr)
  local funcAddr = getDestAddr(addr, true)
  local apiAddr = getApiAddr(funcAddr)
  if apiAddr then
    local scriptStr = [==[
        %x:
        %s
    ]==]
    local address, opcode = disas(addr)
    local ins = string.match(opcode, '^%a+%s+')
    local insStr = string.format("%s %x", ins, apiAddr)
    scriptStr = string.format(scriptStr, addr, insStr)
    autoAssemble(scriptStr)
  end
  return apiAddr
end

function fixs(from, to)
  local pc = from
  local cnt = 0
  while pc < to do
    local destAddr = getDestAddr(pc, true)
    if destAddr and getAddressSafe(destAddr) and not inModule(destAddr) then
      local apiAddr = fix_api(pc)
      if apiAddr then
        cnt = cnt + 1
        print(string.format("(%d) %x[%s] - %s", cnt, pc, getNameFromAddress(pc), getNameFromAddress(apiAddr)))
      end
    end
    pc = pc + getInstructionSize(pc)
  end
  print("Finished")
  return pc
end

local base = getAddress("PROCESS NAME")

local lfanew = readInteger(base + 0x3C)
local peHeader = base + lfanew
local sizeOfCode = readInteger(peHeader + 0x1c)
local baseOfCode = readInteger(peHeader + 0x2c)
local from = base + baseOfCode -- modify base of your module code
local size = sizeOfCode -- modify size of code
local to = from + size
fixs(from, to)
print(string.format("From %x To %x", from, to))
