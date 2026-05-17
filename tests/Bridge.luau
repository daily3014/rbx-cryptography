type HttpGet = (Url: string) -> string
type JSONDecode = <T>(JSON: string) -> T

type Bridge = {
	IsCLI: boolean,

	Get: HttpGet,
	JSONDecode: JSONDecode,
}

zune = (nil) :: {} -- prevent "zune is not defined" error, only works if you set it to nil

local ShouldDetectRuntime = false -- zune doesn't support integers yet and lute can't load modules that yield..
local Bridge: Bridge = {
	-- roblox specific global
	IsCLI = game == nil
}

if Bridge.IsCLI and not integer then
	if not ShouldDetectRuntime then
		error("The runtime you're using is likely outdated or has the integer FFlags disabled!! Use Luau's CLI")
	end

	error("The runtime you're using is likely outdated or has the integer FFlags disabled!! Use Luau's CLI or a runtime that is up to date (e.g Lute)")
end

local function ModuleExists(Path: string): boolean
	return (pcall(require, Path))
end

local function RuntimeHTTPGet(): HttpGet
	if ModuleExists("@lute/luau") then
		local Net = require("@lute/net/client")

		return function(Url: string): string
			local Response = Net.request(Url)

			if not Response.ok then
				error(`HTTP GET failed for URL: {Url}, Status: {Response.status}`)
			end

			return Response.body
		end
	end

	if string.match(_VERSION, "zune") ~= nil then
		local http = zune.net.http

		return function(Url: string): string
			local Response = http.request(Url)

			if not Response.ok then
				error(`HTTP GET failed for URL: {Url}, Status: {Response.status_code} ({Response.status_reason})`)
			end

			return Response.body
		end
	end

	return nil
end

local function RuntimeJSONDecode(): JSONDecode
	if ModuleExists("@lute/luau") then
		local json = require("@std/json")

		return function<T>(JSON: string): T
			return json.deserialize(JSON) :: T
		end
	end

	if string.match(_VERSION, "zune") ~= nil then
		local json = zune.serde.json

		return function<T>(JSON: string): T
			return json.decode(JSON) :: T
		end
	end

	return nil
end

if Bridge.IsCLI then
	if ShouldDetectRuntime then
		Bridge.Get = RuntimeHTTPGet()
		Bridge.JSONDecode = RuntimeJSONDecode()
	end

	local Locations = {
		Tadashi = "../testing/tadashi/"
	}

	local Patterns = {
		Tadashi = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/(.+).json"
	}

	if not Bridge.Get then
		function Bridge.Get(Url: string): string
			-- TYPE ERROR: Pattern is error-type if you use generalized iterator...?
			for Name, Pattern in pairs(Patterns) do
				local Match = string.match(Url, Pattern)

				if not Match then
					continue
				end

				local BaseLocation = Locations[Name]
				local FileLocation = BaseLocation .. Match

				local Success, Contents = pcall(require, FileLocation)

				if not Success then
					error(`Missing file: {FileLocation}, URL: {Url}, Possible Error: {Contents}`)
				end

				return Contents
			end

			error(`Unhandled URL: {Url}`)
		end
	end

	if not Bridge.JSONDecode then
		function Bridge.JSONDecode<T>(JSON: any)
			if type(JSON) ~= "string" then
				return JSON -- already a table (CLI loads via require)
			end

			error("not implemented")
		end
	end
else
	local HttpService = game:GetService("HttpService")

	function Bridge.Get(Url: string): string
		return HttpService:GetAsync(Url)
	end

	function Bridge.JSONDecode<T>(JSON: string)
		return HttpService:JSONDecode(JSON) :: T
	end
end

return Bridge
