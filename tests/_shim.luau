--!strict
--!nolint BuiltinGlobalWrite
--[[
	Standalone-Luau test shim.

	When running under Roblox, returns the real HttpService.
	When running under standalone Luau, returns a fake HttpService that:
		- GetAsync(URL) -> reads the JSON test vector from a Luau-wrapped file
		  in testing/wycheproof/<filename>.luau
		- JSONDecode(str) -> parses JSON via a small inline parser

	JSON files are pre-wrapped as `return [====[<json>]====]` modules so they
	can be require()d (standalone Luau has no io.open / loadfile).

	Test files use this via:
		local Http = require("./_shim")
		local Json = Http:GetAsync(URL); local Data = Http:JSONDecode(Json)
--]]

if game ~= nil then
	return (game :: any):GetService("HttpService") :: any
end

local function ParseJson(Source: string): any
	local Pos, Len = 1, #Source
	local SkipWs, ParseValue, ParseString, ParseNumber, ParseObject, ParseArray, ParseLit
	function SkipWs()
		while Pos <= Len do
			local C = Source:byte(Pos)
			if C == 32 or C == 9 or C == 10 or C == 13 then Pos += 1 else return end
		end
	end
	function ParseString(): string
		Pos += 1
		local Start = Pos
		local Pieces: {string}? = nil
		while Pos <= Len do
			local C = Source:byte(Pos)
			if C == 34 then
				if Pieces then
					table.insert(Pieces, Source:sub(Start, Pos - 1))
					Pos += 1
					return table.concat(Pieces)
				else
					local R = Source:sub(Start, Pos - 1)
					Pos += 1
					return R
				end
			elseif C == 92 then
				if not Pieces then Pieces = {} end
				table.insert(Pieces :: {string}, Source:sub(Start, Pos - 1))
				Pos += 1
				local E = Source:byte(Pos)
				Pos += 1
				if E == 34 then table.insert(Pieces :: {string}, '"')
				elseif E == 92 then table.insert(Pieces :: {string}, '\\')
				elseif E == 47 then table.insert(Pieces :: {string}, '/')
				elseif E == 110 then table.insert(Pieces :: {string}, '\n')
				elseif E == 114 then table.insert(Pieces :: {string}, '\r')
				elseif E == 116 then table.insert(Pieces :: {string}, '\t')
				elseif E == 98 then table.insert(Pieces :: {string}, '\b')
				elseif E == 102 then table.insert(Pieces :: {string}, '\f')
				elseif E == 117 then
					local CP = tonumber(Source:sub(Pos, Pos + 3), 16) :: number
					Pos += 4
					if CP < 0x80 then table.insert(Pieces :: {string}, string.char(CP))
					elseif CP < 0x800 then
						table.insert(Pieces :: {string}, string.char(0xC0 + math.floor(CP / 64), 0x80 + CP % 64))
					else
						table.insert(Pieces :: {string}, string.char(
							0xE0 + math.floor(CP / 4096),
							0x80 + math.floor(CP / 64) % 64,
							0x80 + CP % 64))
					end
				end
				Start = Pos
			else
				Pos += 1
			end
		end
		error("unterminated string")
	end
	function ParseNumber(): number
		local Start = Pos
		while Pos <= Len do
			local C = Source:byte(Pos)
			if (C >= 48 and C <= 57) or C == 45 or C == 43 or C == 46 or C == 69 or C == 101 then
				Pos += 1
			else break end
		end
		return tonumber(Source:sub(Start, Pos - 1)) :: number
	end
	function ParseLit(W: string, V: any): any
		if Source:sub(Pos, Pos + #W - 1) == W then Pos += #W; return V end
		error(`expected {W} at {Pos}`)
	end
	function ParseObject(): any
		Pos += 1
		local R = {}
		SkipWs()
		if Source:byte(Pos) == 125 then Pos += 1; return R end
		while true do
			SkipWs()
			local K = ParseString()
			SkipWs()
			Pos += 1
			SkipWs()
			R[K] = ParseValue()
			SkipWs()
			local C = Source:byte(Pos)
			Pos += 1
			if C == 125 then return R end
		end
	end
	function ParseArray(): any
		Pos += 1
		local R = {}
		SkipWs()
		if Source:byte(Pos) == 93 then Pos += 1; return R end
		while true do
			SkipWs()
			table.insert(R, ParseValue())
			SkipWs()
			local C = Source:byte(Pos)
			Pos += 1
			if C == 93 then return R end
		end
	end
	function ParseValue(): any
		SkipWs()
		local C = Source:byte(Pos)
		if C == 123 then return ParseObject() end
		if C == 91 then return ParseArray() end
		if C == 34 then return ParseString() end
		if C == 116 then return ParseLit("true", true) end
		if C == 102 then return ParseLit("false", false) end
		if C == 110 then return ParseLit("null", nil :: any) end
		return ParseNumber()
	end
	return ParseValue()
end

local function GetAsync(_self: any, Url: string): string
	local Filename = Url:match("([^/]+)%.json$") :: string?
	if not Filename then error(`expected json URL, got {Url}`) end

	-- Each branch uses a literal string require (Luau static analysis requires this)
	if Filename == "aes_gcm_test" then return require("../testing/wycheproof/aes_gcm_test") :: any end
	if Filename == "chacha20_poly1305_test" then return require("../testing/wycheproof/chacha20_poly1305_test") :: any end
	if Filename == "ed25519_test" then return require("../testing/wycheproof/ed25519_test") :: any end
	if Filename == "hkdf_sha256_test" then return require("../testing/wycheproof/hkdf_sha256_test") :: any end
	if Filename == "hkdf_sha512_test" then return require("../testing/wycheproof/hkdf_sha512_test") :: any end
	if Filename == "hmac_sha256_test" then return require("../testing/wycheproof/hmac_sha256_test") :: any end
	if Filename == "hmac_sha3_512_test" then return require("../testing/wycheproof/hmac_sha3_512_test") :: any end
	if Filename == "kmac128_no_customization_test" then return require("../testing/wycheproof/kmac128_no_customization_test") :: any end
	if Filename == "kmac256_no_customization_test" then return require("../testing/wycheproof/kmac256_no_customization_test") :: any end
	if Filename == "mldsa_87_sign_seed_test" then return require("../testing/wycheproof/mldsa_87_sign_seed_test") :: any end
	if Filename == "mldsa_87_verify_test" then return require("../testing/wycheproof/mldsa_87_verify_test") :: any end
	if Filename == "mlkem_1024_test" then return require("../testing/wycheproof/mlkem_1024_test") :: any end
	if Filename == "x25519_test" then return require("../testing/wycheproof/x25519_test") :: any end
	if Filename == "xchacha20_poly1305_test" then return require("../testing/wycheproof/xchacha20_poly1305_test") :: any end
	error(`no shim for {Filename}`)
end

return {
	GetAsync = GetAsync,
	JSONDecode = function(_self: any, Source: string): any
		return ParseJson(Source)
	end,
} :: any
