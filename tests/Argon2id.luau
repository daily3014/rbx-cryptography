--!strict
local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

type TestVector = {
	Description: string,
	Password: string,
	Salt: string,
	TimeCost: number,
	MemoryCost: number,
	Parallelism: number,
	OutputLength: number,
	Secret: string?,
	AssociatedData: string?,
	Expected: string,
}

local Algorithm: any = if IsCLI then require("../src/Hashing/Argon2id") else require("../Hashing/Argon2id")

local TestVectors: {TestVector} = {
	{
		Description = "RFC 9106 §5.3 canonical (m=32, t=3, p=4, secret + AD)",
		Password = string.rep("\x01", 32),
		Salt = string.rep("\x02", 16),
		Secret = string.rep("\x03", 8),
		AssociatedData = string.rep("\x04", 12),
		TimeCost = 3, MemoryCost = 32, Parallelism = 4, OutputLength = 32,
		Expected = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
	},
	{
		Description = "Minimal params (m=8, t=1, p=1)",
		Password = "password",
		Salt = "saltsalt",
		TimeCost = 1, MemoryCost = 8, Parallelism = 1, OutputLength = 32,
		Expected = "78f1d7ead7a95d6bac7fa6fa307f5327e4951ad79ddd1fc5b42931abf5f9515a",
	},
	{
		Description = "Dual-lane (p=2, t=2, m=16)",
		Password = "password",
		Salt = "saltsalt",
		TimeCost = 2, MemoryCost = 16, Parallelism = 2, OutputLength = 32,
		Expected = "2cd58159ed810e1f4716aaeea483af0657c0bb4f2e61197ccf7d7c21de1a1f0f",
	},
	{
		Description = "Truncated tag (OutputLength=16)",
		Password = "password",
		Salt = "saltsalt",
		TimeCost = 1, MemoryCost = 8, Parallelism = 1, OutputLength = 16,
		Expected = "fa830f1085352b133cb1b059bb3e15b0",
	},
	{
		Description = "Long tag (OutputLength=64, exercises H' iteration)",
		Password = "password",
		Salt = "saltsalt",
		TimeCost = 1, MemoryCost = 8, Parallelism = 1, OutputLength = 64,
		Expected = "86d26cf1e488dcd83e22c39e7df0d306eeb36b7277c5999d0198b0e29bb15e7a33ee9f3df2a20375cab742a63230700618512a51b5bb8dbb85c0292320e10fda",
	},
	{
		Description = "Long tag (OutputLength=128, more H' chaining)",
		Password = "password",
		Salt = "saltsalt",
		TimeCost = 1, MemoryCost = 8, Parallelism = 1, OutputLength = 128,
		Expected = "f6847ab51e5dfe782997f77acb3b814c635bd68c1731caaa5b9c1ed09ba6f73c259cfb5bfe179dd50aaa7c6f522c46c14cbaab27f689f7864037e53099227e66559d5d7621879f8062ab4c80d5516032bba782358b4c82dacecd65bb1010f14ec3c3bbe3c4626c685aaef0a6786809593f42f464faa44ccb477c74fc2fa084ee",
	},
	{
		Description = "Higher TimeCost (t=4)",
		Password = "password",
		Salt = "saltsalt",
		TimeCost = 4, MemoryCost = 8, Parallelism = 1, OutputLength = 32,
		Expected = "f0c582e5ecf895d86a5f8311d7f13f57be608b29426d25267674b408a9f1af22",
	},
	{
		Description = "Higher MemoryCost (m=64)",
		Password = "password",
		Salt = "saltsalt",
		TimeCost = 1, MemoryCost = 64, Parallelism = 1, OutputLength = 32,
		Expected = "ef041d9b15f31a1d77d4edb2a1f24e8ae7931c7d6ceaa52ee36d83fd52f96aa7",
	},
	{
		Description = "Sensitivity: different password",
		Password = "Password",
		Salt = "saltsalt",
		TimeCost = 1, MemoryCost = 8, Parallelism = 1, OutputLength = 32,
		Expected = "a3a0e8aa74577fabc77f841554db68b48dee5538f7cc71596eb2687fcd02161c",
	},
	{
		Description = "Sensitivity: different salt",
		Password = "password",
		Salt = "saltsaltX",
		TimeCost = 1, MemoryCost = 8, Parallelism = 1, OutputLength = 32,
		Expected = "086dfc8f4d0e3d63682642f82327f3668c3a26d4f214585efe188611155a18dd",
	},
}

Testing.Describe("Argon2id (RFC 9106) Test Suite", function()
	for _, Vector in TestVectors do
		Testing.Test(Vector.Description, function()
			local Pw = buffer.fromstring(Vector.Password)
			local Sa = buffer.fromstring(Vector.Salt)
			local Options = {
				TimeCost = Vector.TimeCost,
				MemoryCost = Vector.MemoryCost,
				Parallelism = Vector.Parallelism,
				OutputLength = Vector.OutputLength,
				Secret = Vector.Secret and buffer.fromstring(Vector.Secret) or nil,
				AssociatedData = Vector.AssociatedData and buffer.fromstring(Vector.AssociatedData) or nil,
			}
			local Hex = Algorithm(Pw, Sa, Options)
			Testing.Expect(Hex).ToBe(Vector.Expected)
		end)
	end
end)

Testing.Describe("Argon2id Sensitivity Tests", function()
	Testing.Test("Different OutputLength produces different prefix", function()
		local Pw = buffer.fromstring("password")
		local Sa = buffer.fromstring("saltsalt")
		local H32 = Algorithm(Pw, Sa, {TimeCost=1, MemoryCost=8, Parallelism=1, OutputLength=32})
		local H64 = Algorithm(Pw, Sa, {TimeCost=1, MemoryCost=8, Parallelism=1, OutputLength=64})
		Testing.Expect(#H32).ToBe(64)
		Testing.Expect(#H64).ToBe(128)
		Testing.Expect(H32 ~= H64:sub(1, 64)).ToBe(true)
	end)

	Testing.Test("Different Parallelism changes output", function()
		local Pw = buffer.fromstring("password")
		local Sa = buffer.fromstring("saltsalt")
		local H1 = Algorithm(Pw, Sa, {TimeCost=2, MemoryCost=16, Parallelism=1})
		local H2 = Algorithm(Pw, Sa, {TimeCost=2, MemoryCost=16, Parallelism=2})
		Testing.Expect(H1 ~= H2).ToBe(true)
	end)
end)

Testing.Describe("Argon2id Validation Errors", function()
	Testing.Test("Salt too short (< 8 bytes) errors", function()
		Testing.Expect(function()
			Algorithm(buffer.fromstring("pw"), buffer.fromstring("short"))
		end).ToThrow()
	end)

	Testing.Test("MemoryCost < 8 * Parallelism errors", function()
		Testing.Expect(function()
			Algorithm(buffer.fromstring("pw"), buffer.fromstring("saltsalt"), {
				MemoryCost = 4, Parallelism = 2,
			})
		end).ToThrow()
	end)

	Testing.Test("TimeCost < 1 errors", function()
		Testing.Expect(function()
			Algorithm(buffer.fromstring("pw"), buffer.fromstring("saltsalt"), {
				TimeCost = 0,
			})
		end).ToThrow()
	end)

	Testing.Test("Floating point parameters don't error", function()
		local Defaults: {[string]: number} = {TimeCost=1, MemoryCost=8, Parallelism=1, OutputLength=32}

		for _, Param in ipairs({"TimeCost", "MemoryCost", "Parallelism", "OutputLength"}) do
			Testing.Expect(function()
				local Options = {[Param] = Defaults[Param] + 0.5}
				Algorithm(buffer.fromstring("pw"), buffer.fromstring("saltsalt"), Options)
			end).Never.ToThrow()
		end
	end)

	Testing.Test("NaN and Inf values error", function()
		for _, Param in ipairs({"TimeCost", "MemoryCost", "Parallelism", "OutputLength"}) do
			Testing.Expect(function()
				local Options = {[Param] = math.huge}
				Algorithm(buffer.fromstring("pw"), buffer.fromstring("saltsalt"), Options)
			end).ToThrow()

			Testing.Expect(function()
				local Options = {[Param] = math.nan}
				Algorithm(buffer.fromstring("pw"), buffer.fromstring("saltsalt"), Options)
			end).ToThrow()
		end
	end)
end)

Testing.Complete()

return 0
