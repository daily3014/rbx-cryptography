--[=[
	ML-KEM Utilities Module
	
	Utility functions for ML-KEM implementation
	
	Example usage:
		local PubKeySize = Utils.GetKemPublicKeyLen(4) -- 1568 bytes
		local SecKeySize = Utils.GetKemSecretKeyLen(4) -- 3168 bytes
--]=]

--!strict
--!optimize 2
--!native

local MlKemParams = require("./Params")
local Utils = {}

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