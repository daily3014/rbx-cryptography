--[=[
	Cryptography library: True Random Number Generator
	Addon to CSPRNG that mixes in truly random bytes fetched over HTTP.

	CSPRNG.AddEntropy folds whatever bytes you give it into the state
	and regenerates the pool immediately, so fetching real randomness 
	and mixing it in is a single call. One call at startup is enough, 
	the CSPRNG expands that seed into unlimited secure output. A failed
	request returns nil, which AddEntropy treats as a harmless refresh.
--]=]
--!strict
local HttpService = game:GetService("HttpService")

local Cryptography = require(path.to.rbx-cryptography)
local CSPRNG = Cryptography.Utilities.CSPRNG

-- random.org returns the requested number of raw random bytes
local function FetchEntropy(): buffer?
	local Success, Response = pcall(function()
		return HttpService:GetAsync("https://www.random.org/cgi-bin/randbyte?nbytes=32")
	end)

	if not Success then
		warn(`Failed to fetch entropy: {Response}`)
		return nil
	end

	return buffer.fromstring(Response)
end

-- One good seed is enough: the CSPRNG expands it into unlimited secure output,
-- and its internal state already auto-refreshes from local entropy over time.
-- Call this again only if you want fresh external entropy for forward secrecy.
CSPRNG.AddEntropy(FetchEntropy())
