--[=[
	Utility functions for ML-DSA key and signature sizes
	
	 ML-DSA parameters.

	Example usage:
		local Utils = require(script)
		
		local PubKeySize = Utils.PubKeyLen(4, 13)    -- 1312 bytes for ML-DSA-44
		local SecKeySize = Utils.SecKeyLen(4, 4, 2, 13)  -- 2560 bytes
		local SigSize = Utils.SigLen(4, 4, 131072, 80, 128)  -- Variable
--]=]

--!strict
--!optimize 2
--!native

local Q_BIT_WIDTH = 23

local Utils = {}

local function BitWidth(Value: number): number
	if Value == 0 then
		return 0
	end

	local Width = 0
	local TempValue = Value

	while TempValue > 0 do
		Width += 1
		TempValue = bit32.rshift(TempValue, 1)
	end

	return Width
end

function Utils.PubKeyLen(K: number, D: number): number
	local T1Bw = Q_BIT_WIDTH - D
	local PkLen = 32 + K * 32 * T1Bw
	
	return PkLen
end

function Utils.SecKeyLen(K: number, L: number, Eta: number, D: number): number
	local EtaBw = BitWidth(2 * Eta)
	local SkLen = 32 + 32 + 64 + 32 * (EtaBw * (K + L) + K * D)
	
	return SkLen
end

function Utils.SigLen(K: number, L: number, Gamma1: number, Omega: number, Lambda: number): number
	local Gamma1Bw = BitWidth(Gamma1)
	local SigLen = math.floor((2 * Lambda) / 8) + (32 * L * Gamma1Bw) + (Omega + K)
	
	return SigLen
end

function Utils.BitWidth(Value: number): number
	return BitWidth(Value)
end

return Utils