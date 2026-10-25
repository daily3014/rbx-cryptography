--[=[
	Cryptography library: Blake3

	Sizes:
		Key: 32 bytes
		Output: variable

	Return type: string (hex)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring(string.rep("k", 32))

		--------Standard Hash--------
		local Hash = Blake3.Digest(Message, 32)

		--------Keyed Hash--------
		local KeyedHash = Blake3.DigestKeyed(Message, Key, 32)

		--------Key Derivation--------
		local Context = buffer.fromstring("my context")
		local KeyDeriver = Blake3.DeriveKey(Context)
		local DerivedKey = KeyDeriver(Message, 32)
--]=]

--!strict
--!optimize 2
--!native

local EncodingService = if game then game:GetService("EncodingService") else nil
local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex

type Blake3Core = typeof(require("./Blake3Core"))

local Blake3 = {}

local BLAKE3_KEY_SIZE = 32
local BLAKE3_MIN_OUTPUT_BYTES = 1
local BLAKE3_MAX_OUTPUT_BYTES = 2^32 - 1

local LoadedCore: Blake3Core? = nil

local function Core(): Blake3Core
	local Loaded = LoadedCore
	if Loaded then
		return Loaded
	end

	Loaded = require("./Blake3Core")
	LoadedCore = Loaded
	return Loaded
end

local function ValidateLength(Length: number?)
	if Length then
		if typeof(Length) ~= "number" then
			error(`Length must be a number, got {typeof(Length)}`, 3)
		end

		if Length ~= math.floor(Length) then
			error(`Length must be an integer, got {Length}`, 3)
		end

		if Length < BLAKE3_MIN_OUTPUT_BYTES then
			error(`Length must be at least {BLAKE3_MIN_OUTPUT_BYTES} byte, got {Length} bytes`, 3)
		end

		if Length > BLAKE3_MAX_OUTPUT_BYTES then
			error(`Length must be at most {BLAKE3_MAX_OUTPUT_BYTES} bytes, got {Length} bytes`, 3)
		end
	end
end

function Blake3.Digest(Message: buffer, Length: number?): (string, buffer)
	if Message == nil then
		error("Message cannot be nil", 2)
	end

	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	ValidateLength(Length)

	if EncodingService and (Length == nil or Length == 32) then
		local Result = EncodingService:ComputeBufferHash(Message, Enum.HashAlgorithm.Blake3)
		return ToHex(Result), Result
	end

	local Loaded = Core()
	local Result = Loaded.ProcessMessage(Loaded.INITIAL_VECTORS, 0, Message, Length or 32)

	return ToHex(Result), Result
end

function Blake3.DigestBuffer(Message: buffer, Length: number?): buffer
	if Message == nil then
		error("Message cannot be nil", 2)
	end

	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	ValidateLength(Length)

	if EncodingService and (Length == nil or Length == 32) then
		return EncodingService:ComputeBufferHash(Message, Enum.HashAlgorithm.Blake3)
	end

	local Loaded = Core()
	return Loaded.ProcessMessage(Loaded.INITIAL_VECTORS, 0, Message, Length or 32)
end

function Blake3.DigestKeyed(Message: buffer, Key: buffer, Length: number?): (string, buffer)
	if Key == nil then
		error("Key cannot be nil", 2)
	end

	if typeof(Key) ~= "buffer" then
		error(`Key must be a buffer, got {typeof(Key)}`, 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= BLAKE3_KEY_SIZE then
		error(`Key must be exactly {BLAKE3_KEY_SIZE} bytes long, got {KeyLength} bytes`, 2)
	end

	if Message == nil then
		error("Message cannot be nil", 2)
	end
	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	ValidateLength(Length)

	local Loaded = Core()
	local Result = Loaded.ProcessMessage(Key, Loaded.HASH_FLAG, Message, Length or 32)

	return ToHex(Result), Result
end

function Blake3.DeriveKey(Context: buffer): (buffer, number?) -> (string, buffer)
	if Context == nil then
		error("Context cannot be nil", 2)
	end

	if typeof(Context) ~= "buffer" then
		error(`Context must be a buffer, got {typeof(Context)}`, 2)
	end

	local Loaded = Core()
	local ProcessMessage = Loaded.ProcessMessage
	local DeriveMaterialFlag = Loaded.DERIVE_MATERIAL_FLAG
	local ContextHash = ProcessMessage(Loaded.INITIAL_VECTORS, Loaded.DERIVE_CONTEXT_FLAG, Context, 32)

	return function(Material: buffer, Length: number?): (string, buffer)
		if Material == nil then
			error("Material cannot be nil", 2)
		end

		if typeof(Material) ~= "buffer" then
			error(`Material must be a buffer, got {typeof(Material)}`, 2)
		end

		ValidateLength(Length)

		local Result = ProcessMessage(ContextHash, DeriveMaterialFlag, Material, Length or 32)

		return ToHex(Result), Result
	end
end

return Blake3
