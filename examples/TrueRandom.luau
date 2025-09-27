--[=[
	Cryptography library: True Random Number Generator
	Addon to CSPRNG that uses http requests to add extra entropy that is truly random.
	This example shows how to properly use the `AddEntropyProvider` api.
--]=]
--!strict
local HttpService = game:GetService("HttpService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

-- Get the library
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))

-- Create variables for easy access
local CSPRNG = Cryptography.Utilities.CSPRNG
local Conversions = Cryptography.Utilities.Conversions

local MAX_RETRY_ATTEMPTS = 3
local RETRY_BASE_DELAY = 1.0
local EXPECTED_HEX_LENGTH = 2048

local function ValidateHex(HexString: string): (boolean, string?)
	-- Check if string exists
	if not HexString then
		return false, "Hex string is nil"
	end
	
	-- Check if it is a string
	if type(HexString) ~= "string" then
		return false, "Hex string is not a string"
	end

	-- Check if string is empty
	if #HexString == 0 then
		return false, "Hex string is empty"
	end

	-- Check for odd length (hex should always be even number of characters)
	if #HexString % 2 ~= 0 then
		return false, `Hex string has odd length: {#HexString} (expected even)`
	end

	-- Check expected length
	if #HexString ~= EXPECTED_HEX_LENGTH then
		return false, `Unexpected hex length: got {#HexString}, expected {EXPECTED_HEX_LENGTH}`
	end

	-- hex characters (0-9, a-f, A-F)
	local ValidHexPattern = "^[0-9a-fA-F]*$"
	if not string.match(HexString, ValidHexPattern) then
		return false, "Contains invalid hex characters"
	end

	-- All zeros
	if string.match(HexString, "^0+$") then
		return false, "Hex string is all zeros"
	end

	-- All same character
	local FirstChar = string.sub(HexString, 1, 1)
	if string.match(HexString, "^" .. FirstChar .. "+$") then
		return false, `Hex string is all same character '{FirstChar}'`
	end

	-- Basic entropy check
	local UniqueChars = {}
	for i = 1, #HexString do
		local Char = string.sub(HexString, i, i):lower()
		UniqueChars[Char] = true
	end

	local UniqueCount = 0
	for _ in pairs(UniqueChars) do
		UniqueCount += 1
	end

	-- Should have different characters
	if UniqueCount < 8 then
		return false, `Low entropy, only {UniqueCount} unique hex characters`
	end

	return true, nil
end

--[=[
	If the http request fails it will retry with an exponential backoff
	If it does fail after max attempts it will return nil because it is 
	extra entropy so a fallback isn't needed
--]=]
local function Retry(Func: () -> any, MaxAttempts: number): (boolean, buffer?)
	local Attempts = 0
	while Attempts < MaxAttempts do
		Attempts += 1
		local Success, Result = pcall(Func)
		if Success then
			return true, Result
		end
		
		if Attempts < MaxAttempts then
			local WaitTime = RETRY_BASE_DELAY * (2 ^ (Attempts - 1))
			task.wait(WaitTime)
		end
	end
	
	return false
end

-- Quantum random numbers -> https://qrng.anu.edu.au
local function FetchRandom(): buffer?
	local Response = HttpService:GetAsync(`https://qrng.anu.edu.au/wp-content/plugins/colours-plugin/get_block_hex.php?_={DateTime.now().UnixTimestampMillis}`)
	local Valid, ErrorMsg = ValidateHex(Response)
	if not Valid then
		error(`Invalid hex response: {ErrorMsg}`)
	end

	local Result = Conversions.FromHex(Response)
	if buffer.len(Result) ~= EXPECTED_HEX_LENGTH / 2 then
		error(`Unexpected buffer length: got {buffer.len(Result)} bytes, expected {EXPECTED_HEX_LENGTH / 2}`)
	end

	return Result
end

local function GetEntropyBuffer(): buffer?
	local Success, Result = Retry(FetchRandom, MAX_RETRY_ATTEMPTS)
	if Success and Result then
		print(`Added {buffer.len(Result)} bytes of entropy to CSPRNG`)
		return Result
	else
		warn("Failed to fetch entropy after checks")
		return nil
	end
end

-- AddEntropyProvider will only be called once its used up all the entropy from init
-- So you need to do `CSPRNG.Reseed(GetEntropyBuffer())` if you want it from the gecko
CSPRNG.AddEntropyProvider(function()
	return GetEntropyBuffer()
end)

CSPRNG.Reseed(GetEntropyBuffer())

-- Use up the entropy
while task.wait() do
	for i = 1, 32 do
		CSPRNG.RandomHex(256)
	end
end
