--[=[
	Cryptography library: BLAKE2b

	Sizes:
		Output: 1 to 64 bytes (default 64)
		Key: 0 to 64 bytes (optional)

	Example usage:
		local Message = buffer.fromstring("Hello World")

		-- BLAKE2b-512, hex string and buffer
		local Hash, HashBuffer = Blake2b.Digest(Message)

		-- BLAKE2b-256, buffer only
		local HashBuffer256 = Blake2b.DigestBuffer(Message, 32)

		-- With optional key
		local Key = buffer.fromstring("MyKey")
		local KeyedHash, KeyedBuffer = Blake2b.Digest(Message, 64, Key)
--]=]

--!strict
--!optimize 2
--!native

local EncodingService = if game then game:GetService("EncodingService") else nil
local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex

type Blake2bCore = typeof(require("./Blake2bCore"))

local DEFAULT_OUTPUT_BYTES = 64

local BLAKE2B_MIN_OUTPUT_BYTES = 1
local BLAKE2B_MAX_OUTPUT_BYTES = 64
local BLAKE2B_MAX_KEY_BYTES = 64

local LoadedCore: Blake2bCore? = nil

local function Core(): Blake2bCore
	local Loaded = LoadedCore
	if Loaded then
		return Loaded
	end

	Loaded = require("./Blake2bCore")
	LoadedCore = Loaded
	return Loaded
end

local function Validate(InputData: buffer, OutputLength: number?, KeyData: buffer?)
	if InputData == nil then
		error("InputData cannot be nil", 2)
	end

	if typeof(InputData) ~= "buffer" then
		error(`InputData must be a buffer, got {typeof(InputData)}`, 2)
	end

	if OutputLength then
		if typeof(OutputLength) ~= "number" then
			error(`OutputLength must be a number, got {typeof(OutputLength)}`, 2)
		end

		if OutputLength ~= math.floor(OutputLength) then
			error(`OutputLength must be an integer, got {OutputLength}`, 2)
		end

		if OutputLength < BLAKE2B_MIN_OUTPUT_BYTES or OutputLength > BLAKE2B_MAX_OUTPUT_BYTES then
			error(`OutputLength must be between {BLAKE2B_MIN_OUTPUT_BYTES} and {BLAKE2B_MAX_OUTPUT_BYTES} bytes, got {OutputLength} bytes`, 2)
		end
	end

	if KeyData then
		if typeof(KeyData) ~= "buffer" then
			error(`KeyData must be a buffer, got {typeof(KeyData)}`, 2)
		end

		local KeyLength = buffer.len(KeyData)
		if KeyLength == 0 then
			error("KeyData cannot be empty", 2)
		end

		if KeyLength > BLAKE2B_MAX_KEY_BYTES then
			error(`KeyData must be at most {BLAKE2B_MAX_KEY_BYTES} bytes long, got {KeyLength} bytes`, 2)
		end
	end

end

local Blake2b = {}

function Blake2b.Digest(InputData: buffer, OutputLength: number?, KeyData: buffer?): (string, buffer)
	Validate(InputData, OutputLength, KeyData)
	if EncodingService and OutputLength == 32 and KeyData == nil then
		local Result = EncodingService:ComputeBufferHash(InputData, Enum.HashAlgorithm.Blake2b)
		return ToHex(Result), Result
	end

	local Result = Core().Digest(InputData, OutputLength or DEFAULT_OUTPUT_BYTES, KeyData)
	return ToHex(Result), Result
end

function Blake2b.DigestBuffer(InputData: buffer, OutputLength: number?, KeyData: buffer?): buffer
	Validate(InputData, OutputLength, KeyData)
	if EncodingService and OutputLength == 32 and KeyData == nil then
		return EncodingService:ComputeBufferHash(InputData, Enum.HashAlgorithm.Blake2b)
	end

	return Core().Digest(InputData, OutputLength or DEFAULT_OUTPUT_BYTES, KeyData)
end

return Blake2b
