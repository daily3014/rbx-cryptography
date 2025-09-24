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
	--[[
		Since I can't find any error codes i'm going off by the length given
		if its wrong it throws an error which will travel upward into the retry
	]]
	local Response = HttpService:GetAsync(`https://qrng.anu.edu.au/wp-content/plugins/colours-plugin/get_block_hex.php?_={DateTime.now().UnixTimestampMillis}`)
	if Response and #Response  ~= 2048 then
		error(`Unexpected reponse size, got {#Response} expected 2048`)
	end
	
	return Conversions.FromHex(Response)
end

local function GetEntropyBuffer(): buffer?
	local Success, Result = Retry(FetchRandom, MAX_RETRY_ATTEMPTS)
	if Success and Result then
		print(`Added {buffer.len(Result)} bytes to CSPRNG`)
		return Result
	else
		warn("Failed to fetch Random.org entropy")
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
