--[=[
	ML-KEM Polynomial Vector Module
	
	Polynomial vector and matrix operations for ML-KEM.
	Vector arithmetic, matrix multiplication, and encoding/decoding
	operations on vectors of degree-255 polynomials.
--]=]

--!strict
--!optimize 2
--!native

local Ntt = require("./NTT")

local POLY_SIZE = 512

local PolyVec = {}

function PolyVec.VecNtt(Vec: buffer, K: number)
	local NttAt = Ntt.NttAt
	for I = 0, K - 1 do
		NttAt(Vec, I * POLY_SIZE)
	end
end

function PolyVec.VecIntt(Vec: buffer, K: number)
	local InttAt = Ntt.InttAt
	for I = 0, K - 1 do
		InttAt(Vec, I * POLY_SIZE)
	end
end

return PolyVec
