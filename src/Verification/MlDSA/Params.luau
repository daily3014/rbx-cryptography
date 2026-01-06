--[=[
	Parameter validation for ML-DSA algorithms
	
	FIPS 204 specification.

	Example usage:
		local Params = require(script)
		
		local IsValid = Params.CheckKeygenParams(4, 4, 13, 2) -- ML-DSA-44
		local ValidEta = Params.CheckEta(2)
--]=]

--!strict
--!optimize 2
--!native

local Q_BIT_WIDTH = 23
local Q = 8380417

local Params = {}

function Params.CheckEta(Eta: number): boolean
	return Eta == 2 or Eta == 4
end

function Params.CheckNonce(Nonce: number): boolean
	return Nonce == 0 or Nonce == 4 or Nonce == 5 or Nonce == 7
end

function Params.CheckGamma1(Gamma1: number): boolean
	return Gamma1 == bit32.lshift(1, 17) or Gamma1 == bit32.lshift(1, 19)
end

function Params.CheckGamma2(Gamma2: number): boolean
	return Gamma2 == math.floor((Q - 1) / 88) or Gamma2 == math.floor((Q - 1) / 32)
end

function Params.CheckTau(Tau: number): boolean
	return Tau == 39 or Tau == 49 or Tau == 60
end

function Params.CheckD(D: number): boolean
	return D == 13
end

function Params.CheckMatrixDim(ACols: number, BRows: number): boolean
	return ACols == BRows
end

function Params.CheckKeygenParams(K: number, L: number, D: number, Eta: number): boolean
	return (K == 4 and L == 4 and D == 13 and Eta == 2) or
		(K == 6 and L == 5 and D == 13 and Eta == 4) or
		(K == 8 and L == 7 and D == 13 and Eta == 2)
end

function Params.CheckSigningParams(K: number, L: number, D: number, Eta: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	return (K == 4 and L == 4 and D == 13 and Eta == 2 and 
		Gamma1 == bit32.lshift(1, 17) and 
		Gamma2 == math.floor((Q - 1) / 88) and 
		Tau == 39 and Beta == Tau * Eta and Omega == 80 and Lambda == 128) or
		(K == 6 and L == 5 and D == 13 and Eta == 4 and 
			Gamma1 == bit32.lshift(1, 19) and 
			Gamma2 == math.floor((Q - 1) / 32) and 
			Tau == 49 and Beta == Tau * Eta and Omega == 55 and Lambda == 192) or
		(K == 8 and L == 7 and D == 13 and Eta == 2 and 
			Gamma1 == bit32.lshift(1, 19) and 
			Gamma2 == math.floor((Q - 1) / 32) and 
			Tau == 60 and Beta == Tau * Eta and Omega == 75 and Lambda == 256)
end

function Params.CheckVerifyParams(K: number, L: number, D: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	return (K == 4 and L == 4 and D == 13 and 
		Gamma1 == bit32.lshift(1, 17) and 
		Gamma2 == math.floor((Q - 1) / 88) and 
		Tau == 39 and Beta == Tau * 2 and Omega == 80 and Lambda == 128) or
		(K == 6 and L == 5 and D == 13 and 
			Gamma1 == bit32.lshift(1, 19) and 
			Gamma2 == math.floor((Q - 1) / 32) and 
			Tau == 49 and Beta == Tau * 4 and Omega == 55 and Lambda == 192) or
		(K == 8 and L == 7 and D == 13 and 
			Gamma1 == bit32.lshift(1, 19) and 
			Gamma2 == math.floor((Q - 1) / 32) and 
			Tau == 60 and Beta == Tau * 2 and Omega == 75 and Lambda == 256)
end

return Params