--[=[
	ML-KEM Parameters Module
	
	Parameter validation functions for ML-KEM.
	 NIST FIPS 203 specification.

	Example usage:
		local Params = require(script.Params)
		local IsValid = Params.CheckKeygenParams(4, 2) -- true
		
		local ValidD = Params.CheckD(11) -- true
		local ValidEncrypt = Params.CheckEncryptParams(4, 2, 2, 11, 5) -- true
--]=]

--!strict
--!optimize 2
--!native

local Params = {}

function Params.CheckD(D: number): boolean
	return D < 12
end

function Params.CheckEta(Eta: number): boolean
	return (Eta == 2) or (Eta == 3)
end

function Params.CheckK(K: number): boolean
	return (K == 2) or (K == 3) or (K == 4)
end

function Params.CheckL(L: number): boolean
	return (L == 1) or (L == 4) or (L == 5) or (L == 10) or (L == 11) or (L == 12)
end

function Params.CheckMatrixDim(ACols: number, BRows: number): boolean
	return ACols == BRows
end

function Params.CheckKeygenParams(K: number, Eta1: number): boolean
	local Flag0 = (K == 2) and (Eta1 == 3)
	local Flag1 = (K == 3) and (Eta1 == 2)
	local Flag2 = (K == 4) and (Eta1 == 2)

	return Flag0 or Flag1 or Flag2
end

function Params.CheckEncryptParams(K: number, Eta1: number, Eta2: number, Du: number, Dv: number): boolean
	local Flag0 = (K == 2) and (Eta1 == 3) and (Eta2 == 2) and (Du == 10) and (Dv == 4)
	local Flag1 = (K == 3) and (Eta1 == 2) and (Eta2 == 2) and (Du == 10) and (Dv == 4)
	local Flag2 = (K == 4) and (Eta1 == 2) and (Eta2 == 2) and (Du == 11) and (Dv == 5)

	return Flag0 or Flag1 or Flag2
end

function Params.CheckDecryptParams(K: number, Du: number, Dv: number): boolean
	local Flag0 = (K == 2) and (Du == 10) and (Dv == 4)
	local Flag1 = (K == 3) and (Du == 10) and (Dv == 4)
	local Flag2 = (K == 4) and (Du == 11) and (Dv == 5)

	return Flag0 or Flag1 or Flag2
end

function Params.CheckEncapParams(K: number, Eta1: number, Eta2: number, Du: number, Dv: number): boolean
	return Params.CheckEncryptParams(K, Eta1, Eta2, Du, Dv)
end

function Params.CheckDecapParams(K: number, Eta1: number, Eta2: number, Du: number, Dv: number): boolean
	return Params.CheckEncapParams(K, Eta1, Eta2, Du, Dv)
end

return Params