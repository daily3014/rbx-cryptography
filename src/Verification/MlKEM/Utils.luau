--[=[
	ML-KEM Utilities Module
	
	Utility functions for ML-KEM implementation
	
	Example usage:
		local Utils = require(script.Utils)
		local IsEqual = Utils.CtMemcmp(Buffer1, Buffer2)
		
		Utils.CtCondMemcpy(Condition, Dest, Src1, Src2)
		
		local PubKeySize = Utils.GetKemPublicKeyLen(4) -- 1568 bytes
		local SecKeySize = Utils.GetKemSecretKeyLen(4) -- 3168 bytes
--]=]

--!strict
--!optimize 2
--!native

local MlKemParams = require("./Params")

local Utils = {}

function Utils.CtMemcmp(Bytes0: buffer, Bytes1: buffer): number
	local Len0 = buffer.len(Bytes0)
	local Len1 = buffer.len(Bytes1)

	if Len0 ~= Len1 then
		return 0x00000000
	end

	local Flag = 0xFFFFFFFF

	for Index = 0, Len0 - 1 do
		local Byte0 = buffer.readu8(Bytes0, Index)
		local Byte1 = buffer.readu8(Bytes1, Index)

		local Equal = if Byte0 == Byte1 then 0xFFFFFFFF else 0x00000000
		Flag = bit32.band(Flag, Equal)
	end

	return Flag
end

function Utils.CtSelect(Cond: number, A: number, B: number): number
	local Mask = bit32.band(Cond, 0xFFFFFFFF)

	return bit32.bor(
		bit32.band(A, Mask),
		bit32.band(B, bit32.bnot(Mask))
	)
end

function Utils.CtCondMemcpy(Cond: number, Sink: buffer, Source0: buffer, Source1: buffer)
	local SinkLen = buffer.len(Sink)
	local Source0Len = buffer.len(Source0)
	local Source1Len = buffer.len(Source1)

	if not (SinkLen == Source0Len and SinkLen == Source1Len) then
		error("Buffer lengths must match")
	end

	for Index = 0, SinkLen - 1 do
		local Byte0 = buffer.readu8(Source0, Index)
		local Byte1 = buffer.readu8(Source1, Index)

		local Selected = Utils.CtSelect(Cond, Byte0, Byte1)
		buffer.writeu8(Sink, Index, Selected)
	end
end

function Utils.GetPkePublicKeyLen(K: number): number
	if not MlKemParams.CheckK(K) then
		error("Invalid K parameter")
	end

	return K * 12 * 32 + 32
end

function Utils.GetPkeSecretKeyLen(K: number): number
	if not MlKemParams.CheckK(K) then
		error("Invalid K parameter")
	end

	return K * 12 * 32
end

function Utils.GetPkeCipherTextLen(K: number, Du: number, Dv: number): number
	if not MlKemParams.CheckK(K) then
		error("Invalid K parameter")
	end
	if not MlKemParams.CheckD(Du) then
		error("Invalid Du parameter")
	end
	if not MlKemParams.CheckD(Dv) then
		error("Invalid Dv parameter")
	end

	return 32 * (K * Du + Dv)
end

function Utils.GetKemPublicKeyLen(K: number): number
	return Utils.GetPkePublicKeyLen(K)
end

function Utils.GetKemSecretKeyLen(K: number): number
	if not MlKemParams.CheckK(K) then
		error("Invalid K parameter")
	end

	return Utils.GetPkeSecretKeyLen(K) + Utils.GetPkePublicKeyLen(K) + 32 + 32
end

function Utils.GetKemCipherTextLen(K: number, Du: number, Dv: number): number
	return Utils.GetPkeCipherTextLen(K, Du, Dv)
end

return Utils