--!strict
--!optimize 2
--!native

local SkipPackages: {[string]: boolean}, RootName: string, Iterations: number = {}, "rbx-cryptography", 100 do
	local Iters: string?, PackagesList: string?, ComparisonRoot: string? = ...

	if type(PackagesList) == "string" then
		for _, Package in string.split(PackagesList, ",") do
			SkipPackages[Package] = true
		end
	end

	if type(ComparisonRoot) == "string" then
		RootName = ComparisonRoot
	end

    if type(Iters) == "string" then
        assert(tonumber(Iters), `{Iters} is not a valid number`)
        Iterations = tonumber(Iters) :: number
    end
end

type Unit = { Ratio: number, Name: string }
type BenchNode = { Parent: BenchNode?, Name: string, Note: string?, [any]: any }
type Sample = {
	Name: string,
	Size: number,

	Best: number,
	Median: number,
	Selected: number,
	Spread: number,
}

type TargetPath = string | { [string]: string }

type AlternativeSpec = {
	Package: string,
	Path: TargetPath,
	Label: string?,
}

type BenchRow = {
	Name: string,
	Target: TargetPath,
	AltPath: string?,
	Alternatives: { AlternativeSpec }?,
	Params: string?,
	Unit: "Throughput" | "Rate" | "Duration",
}

type BenchSection = {
	Title: string,
	Type: "Comparison" | "Parametric" | "Composite",
	ListLabel: string?,
	AltLabel: string?,
	Rows: { BenchRow },
}

local WARMUP_RUNS = 6
local NOISY_SPREAD = 0.05
local MIN_BATCH_SECONDS = 0.005
local PERCENTILE = 0

local Message = buffer.fromstring(string.rep("A", 1_000_000))
local Key32 = buffer.fromstring(string.rep("B", 32))
local Nonce12 = buffer.fromstring(string.rep("C", 12))
local Salt64 = buffer.fromstring(string.rep("D", 64))
local OutputBytes = 64

local MessageSize = buffer.len(Message)
local Indentations = 0

--local Mu = utf8.char(0x03BC) - messes with string.format padding
local function Duration(Seconds: number): string
	if Seconds >= 3600 then
		local Hours, Minutes = math.modf(Seconds / 3600)
		local Remaining = select(2, math.modf(Minutes / 60))

		return string.format("%.0fh %.0fm %.0fs", Hours, Minutes * 60, Remaining * 60)
	end

	if Seconds >= 60 then
		local Minutes, Remaining = math.modf(Seconds / 60)
		return string.format("%.0fm %.0fs", Minutes, Remaining * 60)
	end

	if Seconds >= 1 then
		return string.format("%.3f s", Seconds)
	end

	if Seconds >= 1e-3 then
		return string.format("%.3f ms", Seconds * 1e3)
	end

	return string.format(`%.1f us`, Seconds * 1e6)
end

local UNITS: { [string]: Unit } = {
	Byte = { Ratio = 1, Name = "B" },
	Kilobyte = { Ratio = 1e3, Name = "KB" },
	Megabyte = { Ratio = 1e6, Name = "MB" },
	Gigabyte = { Ratio = 1e9, Name = "GB" },
	Terabyte = { Ratio = 1e12, Name = "TB" },
}
local function CalculateThroughput(Time: number, Size: number, ForceUnit: keyof<typeof(UNITS)>?): (number, string)
	if ForceUnit then
		local Unit: Unit = UNITS[ForceUnit]
		return Size / Time / Unit.Ratio, `{Unit.Name}/s`
	end

	local LargestRatio, LargestThroughput, LargestName = -1, 0, ""

	for _, Unit in UNITS do
		if Unit.Ratio > LargestRatio then
			local UnitThroughput = Size / Time / Unit.Ratio

			if UnitThroughput < 1 then
				continue
			end

			LargestRatio, LargestThroughput, LargestName = Unit.Ratio, UnitThroughput, Unit.Name
		end
	end

	return LargestThroughput, `{LargestName}/s`
end

assert(loadstring, "Your runtime doesn't support loadstring")

-- prevent deprecated warning
local gc = (loadstring("return collectgarbage") :: () -> (("collect") -> ()) & (("count") -> number))()
assert(gc, "Your runtime doesn't have collectgarbage")
assert((pcall(gc, "collect")), "Your runtime doesn't support collectgarbage with the 'collect' option")

local Sink: any = nil
local function Measure<Args...>(Name: string, Iterations: number, Body: (Args...) -> ...any, ...: Args...): Sample
	for _ = 1, WARMUP_RUNS do
		Sink = Body(...)
	end

	local Probe = os.clock()
	Sink = Body(...)
	local Single = os.clock() - Probe

	local BatchSize = 1
	if Single > 0 and Single < MIN_BATCH_SECONDS then
		BatchSize = math.max(1, math.floor(MIN_BATCH_SECONDS / Single))
	end

	gc("collect")

	local Samples = table.create(Iterations, 0)

	for Index = 1, Iterations do
		local Start = os.clock()
		for _ = 1, BatchSize do
			Sink = Body(...)
		end
		Samples[Index] = (os.clock() - Start) / BatchSize
	end

	table.sort(Samples)

	local Q1 = Samples[math.ceil(0.25 * Iterations)]
	local Q3 = Samples[math.ceil(0.75 * Iterations)]
	local IQR = Q3 - Q1
	local UpperFence = Q3 + (1.5 * IQR)

	local CleanSamples = {}
	for _, SampleTime in Samples do
		if SampleTime <= UpperFence then
			table.insert(CleanSamples, SampleTime)
		end
	end

	local CleanCount = #CleanSamples
	local Best = CleanSamples[1]
	local Median = CleanSamples[(CleanCount + 1) // 2]

	local RankIndex = if PERCENTILE == 0
		then 1
		else math.clamp(math.ceil((PERCENTILE / 100) * CleanCount), 1, CleanCount)

	local Selected = CleanSamples[RankIndex]

	return {
		Name = Name,
		Size = MessageSize,

		Best = Best,
		Median = Median,
		Selected = Selected,
		Spread = if Best > 0 then (Median - Best) / Best else 0,
	}
end

local function FromData(Name: string, Time: number): Sample
	return {
		Name = Name,
		Size = MessageSize,

		Best = Time,
		Median = Time,
		Selected = Time,
		Spread = 0,
	}
end

local function Emit(Text: string, AddIndentations: number?)
	print(string.rep("\t", Indentations) .. Text)
	Indentations += AddIndentations or 0
end

local function Noisy(Result: Sample): string
	return if Result.Spread > NOISY_SPREAD
		then string.format("\t[noisy, median %+.0f%%]", Result.Spread * 100)
		else ""
end

local Benchmarks, Notes = {}, {}
local ActiveNode: BenchNode?

local function CreateNode(Parent: BenchNode?, Name: string?): BenchNode
	local Table = {}

	Table.Parent = Parent
	Table.Name = Name

	return Table :: any
end

local function Package(Name: string, Body: () -> ())
	if SkipPackages[Name] then
		return
	end

	Emit(Name, 1)

	Benchmarks[Name] = CreateNode(nil, Name)
	ActiveNode = Benchmarks[Name]

	local Success, Error = pcall(Body)
	if not Success then
		print(`Library '{Name}' failed with {Error}`)
		Benchmarks[Name] = nil
		Indentations = 0
	else
		Indentations -= 1
	end

	ActiveNode = nil
end

local function Group(Name: string, Body: () -> ())
	assert(ActiveNode, "Called Group(...) without Package(...)")
	Emit(Name, 1)

	local GroupBenchTable = CreateNode(ActiveNode, Name)
	ActiveNode[Name] = GroupBenchTable
	ActiveNode = GroupBenchTable

	Body()
	Indentations -= 1

	if ActiveNode.Parent then
		ActiveNode = ActiveNode.Parent
	end
end

local function Throughput<Args...>(Name: string, Body: (Args...) -> ...any, ...: Args...)
	assert(ActiveNode, "Called Throughput(...) without Group/Package")
	local Result = Measure(Name, Iterations, Body, ...)
	local Amount, Unit = CalculateThroughput(Result.Selected, Result.Size)

	ActiveNode[Name] = Result
	Emit(string.format("%-14s %10.2f %s", Result.Name, Amount, Unit) .. Noisy(Result))
end

local function Rate<Args...>(Name: string, Iterations: number, Body: (Args...) -> ...any, ...: Args...)
	assert(ActiveNode, "Called Rate(...) without Group/Package")
	local Result = Measure(Name, Iterations, Body, ...)

	ActiveNode[Name] = Result
	Emit(string.format("%-14s %9.1f ops/s\t%10s", Result.Name, 1 / Result.Selected, Duration(Result.Selected)) .. Noisy(Result))
end

local function Note(Text: string)
	if ActiveNode then
		ActiveNode.Note = Text
	else
		table.insert(Notes, Text)
	end
end

Note("Generated automatically via the benchmark script at bench/bencher.luau.")
Note("Roundtrip: Complete encrypt/decrypt or sign/verify cycle")

local StartBenchmarking = os.clock()

Package("rbx-cryptography", function()
	local Crypto = require("../src")

	Group("Hashing", function()
		Group("Legacy", function()
			Throughput("MD5", Crypto.Hashing.MD5, Message, nil)
			Throughput("SHA1", Crypto.Hashing.SHA1, Message, nil)
		end)

		Group("SHA2", function()
			Throughput("SHA224", Crypto.Hashing.SHA2.SHA224, Message)
			Throughput("SHA256", Crypto.Hashing.SHA2.SHA256, Message)
			Throughput("SHA384", Crypto.Hashing.SHA2.SHA384, Message)
			Throughput("SHA512", Crypto.Hashing.SHA2.SHA512, Message)
		end)

		Group("SHA3", function()
			Throughput("SHA3-224", Crypto.Hashing.SHA3.SHA3_224, Message)
			Throughput("SHA3-256", Crypto.Hashing.SHA3.SHA3_256, Message)
			Throughput("SHA3-384", Crypto.Hashing.SHA3.SHA3_384, Message)
			Throughput("SHA3-512", Crypto.Hashing.SHA3.SHA3_512, Message)
			Throughput("SHAKE128", Crypto.Hashing.SHA3.SHAKE128, Message, OutputBytes)
			Throughput("SHAKE256", Crypto.Hashing.SHA3.SHAKE256, Message, OutputBytes)
		end)

		Group("Blake", function()
			Throughput("Blake2b", Crypto.Hashing.Blake2b, Message, OutputBytes, nil)
			Throughput("Blake3", Crypto.Hashing.Blake3.Digest, Message, OutputBytes)
		end)

		Group("Argon2id", function()
			local Argon2id = Crypto.Hashing.Argon2id
			local Seed = buffer.fromstring("benchmark password")

			local function Run(TimeCost: number, MemoryCost: number)
				Argon2id(Seed, Salt64, {
					TimeCost = TimeCost,
					MemoryCost = MemoryCost,
					Parallelism = 1,
					OutputLength = 32,
				})
			end

			Rate("Interactive", 5, Run, 2, 8192)
			Rate("Default", 3, Run, 2, 19456)
			Rate("Sensitive", 2, Run, 3, 65536)
		end)

		Group("HKDF", function()
			Throughput("Blake3", Crypto.Hashing.HKDF, Message, Salt64, nil, OutputBytes, Crypto.Hashing.Blake3.Digest, 64, 32)
			Throughput("SHA256", Crypto.Hashing.HKDF, Message, Salt64, nil, OutputBytes, Crypto.Hashing.SHA2.SHA256, 64, 32)
		end)

		Group("HMAC", function()
			Throughput("Blake3", Crypto.Hashing.HMAC, Message, Key32, Crypto.Hashing.Blake3.Digest, 32)
			Throughput("SHA256", Crypto.Hashing.HMAC, Message, Key32, Crypto.Hashing.SHA2.SHA256, 64)
		end)

		Group("KMAC", function()
			local KMAC = Crypto.Hashing.KMAC
			local Output = buffer.create(OutputBytes)

			Throughput("KMAC128", KMAC.KMAC128, Message, Key32, Output, nil)
			Throughput("KMAC256", KMAC.KMAC256, Message, Key32, Output, nil)
		end)
	end)

	Group("Encryption", function()
		Group("ChaCha20", function()
			local ChaCha20 = Crypto.Encryption.AEAD.ChaCha20

			Throughput("Encrypt", ChaCha20, Message, Key32, Nonce12, nil, nil)
			Throughput("Roundtrip", function(Plaintext: buffer, Key: buffer, Nonce: buffer)
				ChaCha20(ChaCha20(Plaintext, Key, Nonce), Key, Nonce)
			end, Message, Key32, Nonce12)
		end)

		Group("AEAD", function()
			local AEAD = Crypto.Encryption.AEAD

			Throughput("Encrypt", AEAD.Encrypt, Message, Key32, Nonce12, nil, nil, nil)
			Throughput("Roundtrip", function(Plaintext: buffer, Key: buffer, Nonce: buffer)
				local Ciphertext, Tag = AEAD.Encrypt(Plaintext, Key, Nonce)
				AEAD.Decrypt(Ciphertext, Key, Nonce, Tag)
			end, Message, Key32, Nonce12)
		end)

		Group("AES-GCM", function()
			local AES = Crypto.Encryption.AES

			Throughput("Encrypt", AES.Encrypt, Message, Key32, Nonce12, nil)
			Throughput("Roundtrip", function(Plaintext: buffer, Key: buffer, InitVector: buffer)
				local Ciphertext, Tag = AES.Encrypt(Plaintext, Key, InitVector)
				AES.Decrypt(Ciphertext, Key, InitVector, Tag)
			end, Message, Key32, Nonce12)
		end)
	end)

	Group("Utilities", function()
		Group("Base64", function()
			local Base64 = Crypto.Utilities.Base64
			local Encoded = Base64.Encode(Message)

			Throughput("Encode", Base64.Encode, Message)
			Throughput("Decode", Base64.Decode, Encoded)
			Throughput("Roundtrip", function(Plaintext: buffer)
				Base64.Decode(Base64.Encode(Plaintext))
			end, Message)
		end)

		Group("Conversions", function()
			Throughput("ToHex", Crypto.Utilities.Conversions.ToHex, Message)
		end)

		Group("CSPRNG", function()
			local CSPRNG = Crypto.Utilities.CSPRNG
			
			Throughput("RandomBytes", CSPRNG.RandomBytes, MessageSize)
			Rate("RandomFloat", 200, CSPRNG.Random)
		end)

		Group("XOR", function()
			local XOR = Crypto.Utilities.XOR
			local Key8 = buffer.fromstring(string.rep("A", 8))
			local Key4 = buffer.fromstring(string.rep("A", 4))

			for _, Key in { Key32, Key8, Key4 } do
				local Size = buffer.len(Key)

				Throughput(`Cipher {Size}`, XOR, Message, Key)
				Throughput(`Roundtrip {Size}`, function(Plaintext: buffer, Key: buffer)
					local Ciphertext = XOR(Plaintext, Key)
					XOR(Ciphertext, Key)
				end, Message, Key)
			end
		end)
	end)

	Group("Verification", function()
		local CSPRNG = Crypto.Utilities.CSPRNG
		local Small = buffer.fromstring("benchmark message")

		Group("EdDSA", function()
			local EdDSA = Crypto.Verification.EdDSA
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = EdDSA.PublicKey(SecretKey)
			local Signature = EdDSA.Sign(Small, SecretKey, PublicKey)

			Rate("Sign", 200, EdDSA.Sign, Small, SecretKey, PublicKey)
			Rate("Verify", 200, EdDSA.Verify, Small, PublicKey, Signature)
		end)

		Group("MlDSA-87", function()
			local MlDSA = Crypto.Verification.MlDSA.ML_DSA_87
			local PublicKey, SecretKey = MlDSA.GenerateKeys()
			local Random = CSPRNG.RandomBytes(32)
			local Context = buffer.create(0)
			local Signature = buffer.create(MlDSA.SigByteLen)
			MlDSA.Sign(Small, Random, SecretKey, Context, Signature)

			Rate("KeyGen", 100, MlDSA.GenerateKeys)
			Rate("Sign", 50, MlDSA.Sign, Small, Random, SecretKey, Context, Signature)
			Rate("Verify", 100, MlDSA.Verify, Small, PublicKey, Context, Signature)
		end)

		Group("X25519", function()
			local X25519 = Crypto.Verification.EdDSA.X25519

			local function GetEd25519ClampedBytes(Input: buffer): buffer
				local Output = buffer.create(32)
				buffer.copy(Output, 0, Input, 0, 32)

				local FirstByte = buffer.readu8(Output, 0)
				FirstByte = bit32.band(FirstByte, 0xF8)
				buffer.writeu8(Output, 0, FirstByte)

				local LastByte = buffer.readu8(Output, 31)
				LastByte = bit32.band(LastByte, 0x7F)
				LastByte = bit32.bor(LastByte, 0x40)
				buffer.writeu8(Output, 31, LastByte)

				local HasVariation = false
				local FirstMiddleByte = buffer.readu8(Output, 1)
				for Index = 2, 30 do
					if buffer.readu8(Output, Index) ~= FirstMiddleByte then
						HasVariation = true
						break
					end
				end

				if not HasVariation then
					buffer.writeu8(Output, 15, bit32.bxor(FirstMiddleByte, 0x55))
				end

				return Output
			end

			local SecretKeyA, SecretKeyB = GetEd25519ClampedBytes(CSPRNG.RandomBytes(32)), GetEd25519ClampedBytes(CSPRNG.RandomBytes(32))
			local PublicKeyB = X25519.PublicKey(SecretKeyB)

			Rate("KeyGen", 200, X25519.PublicKey, SecretKeyA)
			Rate("Exchange", 200, X25519.Exchange, SecretKeyA, PublicKeyB)
		end)

		Group("MlKEM-1024", function()
			local MlKEM = Crypto.Verification.MlKEM.MLKEM_1024
			local PublicKey, SecretKey = MlKEM.GenerateKeys()
			local Seed = CSPRNG.RandomBytes(32)
			local Ciphertext = MlKEM.Encapsulate(Seed, PublicKey)

			Rate("KeyGen", 200, MlKEM.GenerateKeys)
			Rate("Encapsulate", 200, MlKEM.Encapsulate, Seed, PublicKey)
			Rate("Decapsulate", 200, MlKEM.Decapsulate, Ciphertext, SecretKey)
		end)
	end)
end)

Package("RobloxGamerPro200007", function()
	local AES = require("./libraries/raes")

	Group("Encryption", function()
		Group("AES-CTR", function()
			local AES_CTR = AES.new(Key32, AES.modes.CTR, AES.pads.Pkcs7)
			Throughput("Encrypt", AES_CTR.Encrypt, AES_CTR, Message, nil)

			local Encrypted = AES_CTR:Encrypt(Message)
			Throughput("Decrypt", AES_CTR.Decrypt, AES_CTR, Encrypted, nil)
		end)
	end)
end)

Package("EncryptedNet", function()
	local ChaCha = require("./libraries/encryptednet/chacha20")

	local Util = require("./libraries/encryptednet/util")
	local MessageByteArray: any = Util.stringToByteArray(buffer.tostring(Message))
	local KeyByteArray: any = Util.stringToByteArray(buffer.tostring(Key32))
	local NonceByteArray: any = Util.stringToByteArray(buffer.tostring(Nonce12))

	Group("Encryption", function()
		Group("ChaCha20", function()
			Throughput("Encrypt", ChaCha.crypt, MessageByteArray, KeyByteArray, NonceByteArray, nil, nil)
		end)
	end)
end)

Package("HashLib", function()
	local HashLib = require("./libraries/hashlib")

	local MessageString = buffer.tostring(Message)
	local Key32String = buffer.tostring(Key32)

	Group("Hashing", function()
		Group("Legacy", function()
			Throughput("MD5", HashLib.md5, MessageString)
			Throughput("SHA1", HashLib.sha1, MessageString)
		end)

		Group("SHA2", function()
			Throughput("SHA224", HashLib.sha224, MessageString)
			Throughput("SHA256", HashLib.sha256, MessageString)
			Throughput("SHA384", HashLib.sha384, MessageString)
			Throughput("SHA512", HashLib.sha512, MessageString)
		end)

		Group("SHA3", function()
			Throughput("SHA3-224", HashLib.sha3_224, MessageString)
			Throughput("SHA3-256", HashLib.sha3_256, MessageString)
			Throughput("SHA3-384", HashLib.sha3_384, MessageString)
			Throughput("SHA3-512", HashLib.sha3_512, MessageString)
			Throughput("SHAKE128", HashLib.shake128, MessageString, OutputBytes)
			Throughput("SHAKE256", HashLib.shake256, MessageString, OutputBytes)
		end)

		Group("HMAC", function()
			Throughput("SHA256", HashLib.hmac, HashLib.sha256, Key32String, MessageString, false)
		end)
	end)

	Group("Utilities", function()
		Group("Base64", function()
			local Encoded = HashLib.base64_encode(MessageString)
			Throughput("Encode", HashLib.base64_encode, MessageString)
			Throughput("Decode", HashLib.base64_decode, Encoded)

			Throughput("Roundtrip", function(Message: string)
				local Encoded = HashLib.base64_encode(Message)
				HashLib.base64_decode(Encoded)
			end, MessageString)
		end)
	end)
end)

Package("luau-hashing", function()
	local luauhashing = require("./libraries/luauhashing")

	local MessageString = buffer.tostring(Message)

	Group("Hashing", function()
		Group("Legacy", function()
			Throughput("MD5", luauhashing.MD5, MessageString)
			Throughput("SHA1", luauhashing.SHA1, MessageString)
		end)

		Group("SHA2", function()
			Throughput("SHA224", luauhashing.SHA224, MessageString)
			Throughput("SHA256", luauhashing.SHA256, MessageString)
			Throughput("SHA384", luauhashing.SHA384, MessageString)
			Throughput("SHA512", luauhashing.SHA512, MessageString)
		end)

		Group("Blake", function()
			Throughput("Blake2b", luauhashing.Blake2b, MessageString, OutputBytes, nil)
		end)
	end)
end)

Package("Reselim", function()
	local Base64 = require("./algorithms/reselim_base64")

	Group("Utilities", function()
		Group("Base64", function()
			Throughput("Encode", Base64.encode, Message)

			local Encoded = Base64.encode(Message)
			Throughput("Decode", Base64.decode, Encoded)

			Throughput("Roundtrip", function(Message: buffer)
				local Encoded = Base64.encode(Message)
				Base64.decode(Encoded)
			end, Message)
		end)
	end)
end)

Package("Lute", function()
	local Base64 = require("./algorithms/lute_base64")

	Group("Utilities", function()
		Group("Base64", function()
			Throughput("Encode", Base64.encode, Message)

			local Encoded = Base64.encode(Message)
			Throughput("Decode", Base64.decode, Encoded)

			Throughput("Roundtrip", function(Message: buffer)
				local Encoded = Base64.encode(Message)
				Base64.decode(Encoded)
			end, Message)
		end)
	end)
end)

Package("Luau", function()
	Group("Utilities", function()
		Group("math.random", function()
			Note("Unlike CSPRNG, math.random is not suitable for cryptographic use. Finding the seed for a specific sequence of numbers is a trivial task for modern GPUs and CPUs.")

			Throughput("RandomBytes", function(...): ...any
				local Buf = buffer.create(MessageSize)

				for i = 0, buffer.len(Buf) - 1, 4 do
					buffer.writeu32(Buf, i, math.random() * (2 ^ 32 - 1))
				end
			end)

			Rate("RandomFloat", 200, math.random :: () -> ())
		end)

		Group("XOR", function()
			local Key32String = string.rep("A", 32)

			-- way too slow, even with one iteration..
			local OldIterations = Iterations
			MessageSize = 100_000
			local MessageString = string.rep("A", MessageSize)

			Iterations = math.min(Iterations, 10)
			Throughput(`string.char`, function(Message: string, Key: string)
				local MessageLength, KeyLength = #Message, #Key

				local Result = ""
				for Index = 1, MessageLength do
					local Byte = string.byte(Message, Index, Index)
					local KeyPosition = ((Index - 1) % KeyLength) + 1
					local KeyByte = string.byte(Key, KeyPosition, KeyPosition)

					Result ..= string.char(bit32.bxor(Byte, KeyByte))
				end

				return Result
			end, MessageString, Key32String)

			Iterations = OldIterations
			MessageSize = buffer.len(Message)
			MessageString = buffer.tostring(Message)

			Throughput(`string.gsub`, function(Message: string, Key: string)
				local Index, KeyLength = 0, #Key
				return Message:gsub(".", function(Character: string)
					Index += 1

					local Byte = string.byte(Character)
					local KeyPosition = ((Index - 1) % KeyLength) + 1
					local KeyByte = string.byte(Key, KeyPosition, KeyPosition)

					return string.char(bit32.bxor(Byte, KeyByte))
				end)
			end, MessageString, Key32String)

			Throughput(`table.concat`, function(Message: string, Key: string)
				local KeyLength = #Key
				local Characters = string.split(Message, "")

				for Index, Character in Characters do
					local Byte = string.byte(Message, Index, Index)
					local KeyPosition = ((Index - 1) % KeyLength) + 1
					local KeyByte = string.byte(Key, KeyPosition, KeyPosition)

					Characters[Index] = string.char(bit32.bxor(Byte, KeyByte))
				end

				return table.concat(Characters, "")
			end, MessageString, Key32String)
		end)
	end)
end)

Package("WASM", function()
	Group("Verification", function()
		local Small = buffer.fromstring("benchmark message")

		Group("MlDSA-87", function()
			local MlDSA = require("./libraries/wasm_mldsa87/library")
			local State = MlDSA.generate()
			local Context = ""
			
			local Signature = MlDSA.sign(State, Small, Context)
			assert(Signature, "WASM MlDSA-87 returned nil for MlDSA.sign")

			Rate("KeyGen", 100, MlDSA.generate)
			Rate("Sign", 50, MlDSA.sign, State, Small, Context)
			Rate("Verify", 100, MlDSA.verify, State, Small, Context, Signature)
		end)

		Group("MlKEM-1024", function()
			local MlKEM = require("./libraries/wasm_mklem1024/library")
			local State = MlKEM.generate()
			local Ciphertext = MlKEM.encapsulate(State)

			Rate("KeyGen", 200, MlKEM.generate)
			Rate("Encapsulate", 200, MlKEM.encapsulate, State)
			Rate("Decapsulate", 200, MlKEM.decapsulate, State, Ciphertext)
		end)
	end)
end)

Package("ccryptolib", function()
	local MessageString = buffer.tostring(Message)
	local Key32String, Nonce12String = buffer.tostring(Key32), buffer.tostring(Nonce12)

	Group("Hashing", function()
		Group("SHA2", function()
			local SHA256 = require("./libraries/ccryptolib/sha256")
			local SHA512 = require("./libraries/ccryptolib/internal/sha512")

			Throughput("SHA256", SHA256.digest, MessageString)
			Throughput("SHA512", SHA512.digest, MessageString)
		end)

		Group("Blake", function()
			local Blake3 = require("./libraries/ccryptolib/blake3")
			Throughput("Blake3", Blake3.digest, MessageString :: any, OutputBytes :: any)
		end)
	end)

	Group("Encryption", function()
		Group("ChaCha20", function()
			local ChaCha20 = require("./libraries/ccryptolib/chacha20")

			Throughput("Encrypt", ChaCha20.crypt, Key32String, Nonce12String, MessageString, nil :: any, nil :: any)
			Throughput("Roundtrip", function(Plaintext: string, Key: string, Nonce: string)
				ChaCha20.crypt(Key, Nonce, ChaCha20.crypt(Key, Nonce, Plaintext, nil :: any, nil :: any), nil :: any, nil :: any)
			end, MessageString, Key32String, Nonce12String)
		end)

		Group("AEAD", function()
			local AEAD = require("./libraries/ccryptolib/aead")
			local AAD = "additional data"

			Throughput("Encrypt", AEAD.encrypt, Key32String, Nonce12String, MessageString, AAD, nil :: any)
			Throughput("Roundtrip", function(Plaintext: string, Key: string, Nonce: string)
				local Ciphertext, Tag = AEAD.encrypt(Key32String, Nonce12String, MessageString, AAD, nil :: any)
				AEAD.decrypt(Key, Nonce, Tag, Ciphertext, AAD, nil :: any)
			end, MessageString, Key32String, Nonce12String)
		end)
	end)

	Group("Verification", function()
		local CSPRNG = require("../src/Utilities/CSPRNG")
		local Small = "benchmark message"

		Group("EdDSA", function()
			local EdDSA = require("./libraries/ccryptolib/ed25519")
			local SecretKey = buffer.tostring(CSPRNG.RandomBytes(32))
			local PublicKey = EdDSA.publicKey(SecretKey)
			local Signature = EdDSA.sign(SecretKey, PublicKey, Small)

			Rate("Sign", 200, EdDSA.sign, SecretKey, PublicKey, Small)
			Rate("Verify", 200, EdDSA.verify, PublicKey, Small, Signature :: any)
		end)

		Group("X25519", function()
			local X25519 = require("./libraries/ccryptolib/x25519c")

			local SecretKeyA, SecretKeyB =
				buffer.tostring(CSPRNG.RandomBytes(64)),
				buffer.tostring(CSPRNG.RandomBytes(64))
			local PublicKeyB = X25519.publicKey(SecretKeyB :: any)

			Rate("KeyGen", 200, X25519.publicKey, SecretKeyA :: any)
			Rate("Exchange", 200, X25519.exchange, SecretKeyA :: any, PublicKeyB)
		end)
	end)
end)

-- Benched inside Roblox Studio
Benchmarks.Roblox = {
	Name = "Roblox",
	Utilities = {
		Base64 = {
			Encode = FromData("Encode", MessageSize / (1.12 * UNITS.Gigabyte.Ratio)), -- 1.17GB/s
			Decode = FromData("Decode", MessageSize / (1.80 * UNITS.Gigabyte.Ratio)), -- 1.80GB/s
			Roundtrip = FromData("Roundtrip", MessageSize / (683.90 * UNITS.Megabyte.Ratio)), -- 683.90MB/s
		}
	}
}

local EndBenchmarking = os.clock() - StartBenchmarking
print(`Finished benchmarking - took {Duration(EndBenchmarking)}`)

local SUPERSCRIPTS = {
	["0"] = utf8.char(0x2070),
	["1"] = utf8.char(0x00B9),
	["2"] = utf8.char(0x00B2),
	["3"] = utf8.char(0x00B3),
	["4"] = utf8.char(0x2074),
	["5"] = utf8.char(0x2075),
	["6"] = utf8.char(0x2076),
	["7"] = utf8.char(0x2077),
	["8"] = utf8.char(0x2078),
	["9"] = utf8.char(0x2079),
}

local NoteMap: { [string]: number } = {}
local Footnotes: { string } = {}

local function ToSuperScript(Number: number): string
	return (string.gsub(tostring(Number), ".", SUPERSCRIPTS))
end

local function ResolvePath<T>(Root: BenchNode?, PathString: string): T?
	if not Root then
		return nil
	end

	local Current: any = Root

	for _, Key in string.split(PathString, "/") do
		if type(Current) ~= "table" then return nil end
		Current = Current[Key]
	end

	return if type(Current) == "table"
		then Current
		else nil
end

local function GetNotesForPath(Root: BenchNode?, PathString: string, Acc: { string })
	if not Root then return end
	local Current: any = Root
	if Current.Note then
		table.insert(Acc, Current.Note)
	end

	for _, Key in string.split(PathString, "/") do
		if type(Current) ~= "table" then break end
		Current = Current[Key]
		if type(Current) == "table" and Current.Note then
			table.insert(Acc, Current.Note)
		end
	end
end

local function GetDisplay(Root: BenchNode?, Target: TargetPath?, Label: string): string
	if not Root or not Target then
		return Label
	end

	local AssociatedNotes: { string } = {}

	if type(Target) == "string" then
		GetNotesForPath(Root, Target, AssociatedNotes)
	elseif type(Target) == "table" then
		for _, Path in Target do
			GetNotesForPath(Root, Path, AssociatedNotes)
		end
	end

	if #AssociatedNotes == 0 then
		return Label
	end

	local Scripts = {}
	for _, NoteText in AssociatedNotes do
		local Index = NoteMap[NoteText]

		if not Index then
			table.insert(Footnotes, NoteText)
			Index = #Footnotes
			NoteMap[NoteText] = Index
		end

		table.insert(Scripts, ToSuperScript(Index))
	end

	local UniqueScripts = {}
	local Seen = {}
	for _, Script in Scripts do
		if not Seen[Script] then
			Seen[Script] = true
			table.insert(UniqueScripts, Script)
		end
	end

	return Label .. table.concat(UniqueScripts, "")
end

local function FormatSpeedup(TargetVal: number, AltVal: number, Reverse: boolean?): string
	if AltVal <= 0 or TargetVal <= 0 then
		return "-"
	end

	local Ratio = if Reverse then AltVal / TargetVal else TargetVal / AltVal

	if Ratio >= 1 then
		return string.format("**%.1fx faster**", Ratio)
	else
		return string.format("%.1fx slower", 1 / Ratio)
	end
end

local function FormatThroughput(Sample: Sample?, CustomBytes: number?): (string, number)
	if not Sample then
		return "-", 0
	end

	local Size = CustomBytes or Sample.Size or MessageSize

	local Amount, UnitStr = CalculateThroughput(Sample.Selected, Size)
	local RawMBs = CalculateThroughput(Sample.Selected, Size, "Megabyte")

	local Formatted = if Amount >= 10 or Amount == math.floor(Amount)
		then string.format("%.0f %s", Amount, UnitStr)
		else string.format("%.1f %s", Amount, UnitStr)

	return Formatted, RawMBs
end

local function Alternatives(
	Row: BenchRow,
	RbxName: string,
	AllBenchmarks: { [string]: BenchNode }
): { AlternativeSpec }
	local Results: { AlternativeSpec } = {}
	local SeenPackages: { [string]: boolean } = {}

	if Row.Alternatives then
		for _, Alt in Row.Alternatives do
			table.insert(Results, Alt)
			SeenPackages[Alt.Package] = true
		end
	end

	local AutoSearchPath: string? = Row.AltPath or (if type(Row.Target) == "string" then Row.Target else nil)

	if AutoSearchPath then
		local AutoDiscovered: { AlternativeSpec } = {}

		for PkgName, PkgRoot in AllBenchmarks do
			if PkgName == RbxName or SeenPackages[PkgName] then
				continue
			end

			local Sample = ResolvePath(PkgRoot, AutoSearchPath)
			if Sample then
				table.insert(AutoDiscovered, {
					Package = PkgName,
					Path = AutoSearchPath,
				})
			end
		end

		table.sort(AutoDiscovered, function(a: AlternativeSpec, b: AlternativeSpec)
			return a.Package < b.Package
		end)

		for _, Alt in AutoDiscovered do
			table.insert(Results, Alt)
		end
	end

	return Results
end

local function PadCell(Cell: string, TargetWidth: number): string
	local VisualLen = utf8.len(Cell) or #Cell
	local MissingSpaces = math.max(0, TargetWidth - VisualLen)
	return Cell .. string.rep(" ", MissingSpaces)
end

local function FitGrid(Grid: { { string } }): string
	if #Grid == 0 then
		return ""
	end

	local Columns = #Grid[1]
	local ColumnWidths = table.create(Columns, 0)

	for _, Row in Grid do
		for Index, Cell in Row do
			local VisualLen = utf8.len(Cell) or #Cell
			ColumnWidths[Index] = math.max(ColumnWidths[Index] or 0, VisualLen)
		end
	end

	for Index = 1, Columns do
		ColumnWidths[Index] = math.max(3, ColumnWidths[Index])
	end

	local Lines = {}
	do
		local HeaderCells, SeparatorCells = {}, {}

		for Index, Cell in Grid[1] do
			table.insert(HeaderCells, PadCell(Cell, ColumnWidths[Index]))
		end

		for ColIdx = 1, Columns do
			table.insert(SeparatorCells, string.rep("-", ColumnWidths[ColIdx]))
		end

		table.insert(Lines, "| " .. table.concat(HeaderCells, " | ") .. " |")
		table.insert(Lines, "| " .. table.concat(SeparatorCells, " | ") .. " |")
	end

	for RowIndex = 2, #Grid do
		local RowCells = {}

		for ColumnIndex, Cell in Grid[RowIndex] do
			table.insert(RowCells, PadCell(Cell, ColumnWidths[ColumnIndex]))
		end

		table.insert(Lines, "| " .. table.concat(RowCells, " | ") .. " |")
	end

	return table.concat(Lines, "\n")
end

local function Build(Section: BenchSection, Root: BenchNode, AllBenchmarks: { [string]: BenchNode }): string
	assert(Root and Root.Name, `Root lacks the Name field`)
	local Grid: { { string } } = {}

	if Section.Type == "Comparison" then
		local ListHeader = Section.ListLabel or "Algorithm"
		local AltHeader = Section.AltLabel or "Alternative"
		table.insert(Grid, { ListHeader, Root.Name, AltHeader, "Improvement" })

		for _, Row in Section.Rows do
			local TargetSample = ResolvePath(Root, Row.Target :: string) :: Sample
			local TargetDisplay, TargetMBs = FormatThroughput(TargetSample)
			local BoldTarget = if TargetSample then `**{TargetDisplay}**` else "-"

			local AltDisplays, Improvements = {}, {}
			local Alternatives = Alternatives(Row, Root.Name, AllBenchmarks)

			for _, Alt in Alternatives do
				local AltRoot = AllBenchmarks[Alt.Package]
				local AltSample = if AltRoot then ResolvePath(AltRoot, Alt.Path :: string) :: Sample else nil

				if AltSample then
					local Display, AltMBs = FormatThroughput(AltSample)
					local Label = Alt.Label or Alt.Package
					table.insert(AltDisplays, `{Display} ({GetDisplay(AltRoot, Alt.Path, Label)})`)
					table.insert(Improvements, `{FormatSpeedup(TargetMBs, AltMBs)} than {Label}`)
				end
			end

			local AltStr = if #AltDisplays > 0 then table.concat(AltDisplays, "<br>") else "-"
			local ImpStr = if #Improvements > 0 then table.concat(Improvements, "<br>") else "-"

			table.insert(Grid, { GetDisplay(Root, Row.Target, Row.Name), BoldTarget, AltStr, ImpStr })
		end

	elseif Section.Type == "Parametric" then
		local ListHeader = Section.ListLabel or "Tier"
		table.insert(Grid, { ListHeader, "Parameters", Root.Name })

		for _, Row in Section.Rows do
			local TargetSample = ResolvePath(Root, Row.Target :: string) :: Sample
			local Display = "-"

			if TargetSample then
				local Ops = 1 / TargetSample.Selected
				local Latency = Duration(TargetSample.Selected)
				Display = string.format("**%.0f op/s - %s**", Ops, Latency)
			end

			table.insert(Grid, { GetDisplay(Root, Row.Target, Row.Name), Row.Params or "-", Display })
		end

	elseif Section.Type == "Composite" then
		local ListColHeader = Section.ListLabel or "Algorithm"
		local AltColHeader = Section.AltLabel or "Alternative"
		table.insert(Grid, { ListColHeader, "Time", AltColHeader, "Improvement" })

		for _, Row in Section.Rows do
			local TargetLines = {}
			local TotalTargetTime = 0

			if type(Row.Target) == "table" then
				for Label, Path in Row.Target do
					local Sample = ResolvePath(Root, Path) :: Sample

					if Sample then
						TotalTargetTime += Sample.Selected
						table.insert(TargetLines, `{Label}: **{Duration(Sample.Selected)}**`)
					end
				end

				if #TargetLines > 1 then
					table.insert(TargetLines, 1, `Roundtrip: **{Duration(TotalTargetTime)}**`)
				end
			else
				local Sample = ResolvePath(Root, Row.Target) :: Sample

				if Sample then
					TotalTargetTime = Sample.Selected
					table.insert(TargetLines, `**{Duration(Sample.Selected)}**`)
				end
			end

			local TargetDisplay = if #TargetLines > 0 then table.concat(TargetLines, "<br>") else "-"
			local AltString, ImpString = "-", "-"
			local AlternativesList = Alternatives(Row, Root.Name, AllBenchmarks)

			if #AlternativesList > 0 then
				local AltDisplays, Improvements = {}, {}

				for _, Alt in AlternativesList do
					local AltRoot = AllBenchmarks[Alt.Package]
					if not AltRoot then
						continue
					end

					local TotalAltTime = 0
					local ValidAlt = false

					if type(Alt.Path) == "table" then
						for _, Path in Alt.Path do
							local Sample = ResolvePath(AltRoot, Path) :: Sample
							if Sample then
								TotalAltTime += Sample.Selected
								ValidAlt = true
							end
						end
					elseif type(Alt.Path) == "string" then
						local Sample = ResolvePath(AltRoot, Alt.Path) :: Sample
						if Sample then
							TotalAltTime = Sample.Selected
							ValidAlt = true
						end
					end

					if ValidAlt then
						local Label = Alt.Label or Alt.Package
						table.insert(AltDisplays, `{Duration(TotalAltTime)} ({GetDisplay(AltRoot, Alt.Path, Label)})`)
						table.insert(Improvements, FormatSpeedup(TotalTargetTime, TotalAltTime, true))
					end
				end

				if #AltDisplays > 0 then
					AltString = table.concat(AltDisplays, "<br>")
					ImpString = table.concat(Improvements, "<br>")
				end
			end

			table.insert(Grid, { GetDisplay(Root, Row.Target, Row.Name), TargetDisplay, AltString, ImpString })
		end
	end

	return `### {Section.Title}\n\n` .. FitGrid(Grid)
end

local BenchStructure: { BenchSection } = {
	{
		Title = "Hashing",
		Type = "Comparison",
		Rows = {
			{ Name = "SHA-256", Target = "Hashing/SHA2/SHA256", Unit = "Throughput" },
			{ Name = "SHA-512", Target = "Hashing/SHA2/SHA512", Unit = "Throughput" },
			{ Name = "SHA3-512", Target = "Hashing/SHA3/SHA3-512", Unit = "Throughput" },
			{ Name = "BLAKE2B", Target = "Hashing/Blake/Blake2b", Unit = "Throughput" },
			{ Name = "BLAKE3", Target = "Hashing/Blake/Blake3", Unit = "Throughput" },
			{ Name = "HMAC-BLAKE3", Target = "Hashing/HMAC/Blake3", Unit = "Throughput" },
			{ Name = "KMAC-128", Target = "Hashing/KMAC/KMAC128", Unit = "Throughput" },
			{ Name = "KMAC-256", Target = "Hashing/KMAC/KMAC256", Unit = "Throughput" },
		},
	},

	{
		Title = "Password Hashing (Argon2id)",
		Type = "Parametric",
		ListLabel = "Tier",
		Rows = {
			{
				Name = "Interactive",
				Params = "m=8 MiB, t=2, p=1",
				Target = "Hashing/Argon2id/Interactive",
				Unit = "Rate",
			},
			{
				Name = "Default",
				Params = "m=19 MiB, t=2, p=1",
				Target = "Hashing/Argon2id/Default",
				Unit = "Rate",
			},
			{
				Name = "Sensitive",
				Params = "m=64 MiB, t=3, p=1",
				Target = "Hashing/Argon2id/Sensitive",
				Unit = "Rate",
			},
		},
	},

	{
		Title = "Encryption",
		Type = "Comparison",
		Rows = {
			{ Name = "ChaCha20 (Encrypt)", Target = "Encryption/ChaCha20/Encrypt", Unit = "Throughput" },
			{ Name = "ChaCha20-Poly1305 (Encrypt)", Target = "Encryption/AEAD/Encrypt", Unit = "Throughput" },

			{
				Name = "AES-GCM (Encrypt)",
				Target = "Encryption/AES-GCM/Encrypt",
				Unit = "Throughput",
				Alternatives = {
					{
						Package = "RobloxGamerPro200007",
						Path = "Encryption/AES-CTR/Encrypt",
						Label = "RobloxGamerPro200007 AES256-CTR",
					},
				},
			},
		},
	},

	{
		Title = "Digital Signatures & Key Exchange",
		Type = "Composite",
		Rows = {
			{
				Name = "EdDSA",
				Target = {
					Sign = "Verification/EdDSA/Sign",
					Verify = "Verification/EdDSA/Verify",
				},
				Unit = "Duration",
				Alternatives = {
					{
						Package = "ccryptolib",
						Path = {
							Sign = "Verification/EdDSA/Sign",
							Verify = "Verification/EdDSA/Verify",
						},
						Label = "ccryptolib",
					},
				},
			},

			{
				Name = "ML-DSA-87",
				Target = {
					KeyGen = "Verification/MlDSA-87/KeyGen",
					Sign = "Verification/MlDSA-87/Sign",
					Verify = "Verification/MlDSA-87/Verify",
				},
				Unit = "Duration",
				Alternatives = {
					{
						Package = "WASM",
						Path = {
							KeyGen = "Verification/MlDSA-87/KeyGen",
							Sign = "Verification/MlDSA-87/Sign",
							Verify = "Verification/MlDSA-87/Verify",
						},
						Label = "WASM",
					},
				},
			},

			{
				Name = "X25519",
				Target = {
					KeyGen = "Verification/X25519/KeyGen",
					Exchange = "Verification/X25519/Exchange",
				},
				Unit = "Duration",
				Alternatives = {
					{
						Package = "ccryptolib",
						Path = {
							KeyGen = "Verification/X25519/KeyGen",
							Exchange = "Verification/X25519/Exchange",
						},
						Label = "ccryptolib",
					},
				},
			},

			{
				Name = "ML-KEM-1024",
				Target = {
					KeyGen = "Verification/MlKEM-1024/KeyGen",
					Encap = "Verification/MlKEM-1024/Encapsulate",
					Decap = "Verification/MlKEM-1024/Decapsulate",
				},
				Unit = "Duration",
				Alternatives = {
					{
						Package = "WASM",
						Path = {
							KeyGen = "Verification/MlKEM-1024/KeyGen",
							Encap = "Verification/MlKEM-1024/Encapsulate",
							Decap = "Verification/MlKEM-1024/Decapsulate",
						},
						Label = "WASM",
					},
				},
			},
		},
	},

	{
		Title = "Utilities",
		Type = "Comparison",
		Rows = {
			{ Name = "Base64 (Encode)", Target = "Utilities/Base64/Encode", Unit = "Throughput" },
			{ Name = "Base64 (Decode)", Target = "Utilities/Base64/Decode", Unit = "Throughput" },
			{ Name = "Base64 (Roundtrip)", Target = "Utilities/Base64/Roundtrip", Unit = "Throughput" },

			{
				Name = "CSPRNG (RandomBytes)",
				Target = "Utilities/CSPRNG/RandomBytes",
				Unit = "Throughput",
				Alternatives = {
					{
						Package = "Luau",
						Path = "Utilities/math.random/RandomBytes",
						Label = "math.random",
					},
				},
			},

			{
				Name = "XOR",
				Target = "Utilities/XOR/Cipher 32",
				Unit = "Throughput",
				Alternatives = {
					{
						Package = "Luau",
						Path = "Utilities/XOR/string.char",
						Label = "string.char",
					},

					{
						Package = "Luau",
						Path = "Utilities/XOR/string.gsub",
						Label = "string.gsub",
					},

					{
						Package = "Luau",
						Path = "Utilities/XOR/table.concat",
						Label = "table.concat",
					},
				},
			},
		},
	},
}

assert(Benchmarks[RootName], `{RootName} wasn't found in the benchmarks`)

print(`Iterations: {Iterations} (P{PERCENTILE} throughput/rate), warmup {WARMUP_RUNS}`)
print(`Message size: {MessageSize} bytes`)
print(`Output bytes: {OutputBytes}`)
print("")

for _, Section in BenchStructure do
	print(Build(Section, Benchmarks[RootName], Benchmarks))
	print("\n")
end

if #Footnotes > 0 then
	for Index, FootnoteText in Footnotes do
		print(`{ToSuperScript(Index)} {FootnoteText}`)
	end
	print("")
end

for Index, Annotation in Notes do
	print(`\\* {Annotation}{if Index ~= #Notes then "\\" else ""}`)
end

assert(Sink or not Sink)