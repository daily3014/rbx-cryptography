--[=[
	Cryptography library: True Random Number Generator
	Addon to CSPRNG that uses http requests to add extra entropy that is truly random.
	This example shows how to properly use the `AddEntropyProvider` api.
	
	BytesLeft Info:
		CSPRNG.BytesLeft shows how many bytes are available for entropy providers.
		On init, the default entropy sources use 312 bytes, leaving 712 bytes free.
		When you call Reseed() it always uses 312 bytes (unless changed) for default entropy, leaving 712.
		Your custom entropy providers get called with BytesLeft parameter to know the limit.
		If you return more bytes than available, CSPRNG will truncate and scream at you.
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

	return true, nil
end

--[=[
	If the http request fails it will retry with an exponential backoff
	If it does fail after max attempts, it will return nil because it is  extra entropy, so no fallback needed
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

local function GetEntropyBuffer(BytesLeft: number): buffer?
	-- BytesLeft tells us how many bytes we can add without getting yelled at
	-- CSPRNG uses 312 bytes (unless changed) for default entropy, leaving 712 bytes free
	-- This function gets 1024 bytes from the API but we truncate it to BytesLeft
	-- so CSPRNG doesn't scream at us about returning too much

	local Success, Result = Retry(FetchRandom, MAX_RETRY_ATTEMPTS)
	if Success and Result then
		local FetchedSize = buffer.len(Result)
		local TruncatedSize = math.min(FetchedSize, BytesLeft)

		-- Truncate to BytesLeft so we don't get warnings from CSPRNG
		if FetchedSize > BytesLeft then
			local Truncated = buffer.create(BytesLeft)
			buffer.copy(Truncated, 0, Result, 0, BytesLeft)
			print(`Added {TruncatedSize} bytes of entropy to CSPRNG ({FetchedSize} fetched, truncated to {BytesLeft} available)`)
			return Truncated
		end

		print(`Added {TruncatedSize} bytes of entropy to CSPRNG`)
		return Result
	else
		warn("Failed to fetch entropy after all retry attempts")
		return nil
	end
end

-- Check how many bytes are available for custom entropy
print(`CSPRNG has {CSPRNG.BytesLeft} bytes available for custom entropy providers`)

-- Manual reseed to get the quantum entropy right away
-- This uses the same 312 bytes for default entropy, leaving 712 for our custom entropy
CSPRNG.Reseed(GetEntropyBuffer(CSPRNG.BytesLeft))

-- AddEntropyProvider will only be called once it uses up all the entropy from init
-- So you need to manually reseed first if you want the extra entropy from the start
CSPRNG.AddEntropyProvider(GetEntropyBuffer)

-- Use up the entropy so you can see when AddEntropyProvider gets called again
while task.wait() do
	for i = 1, 32 do
		CSPRNG.RandomHex(256)
	end
end