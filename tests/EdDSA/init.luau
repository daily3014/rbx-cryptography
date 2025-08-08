--!strict
local Testing = require("./")

type Wycheproof = {
	TestName: string,
	Secret: string,
	CounterKey: string,
	K: string,
	ShouldFail: boolean
}

type Ed25519TestVector = {
	PrivateKey: string,
	PublicKey: string,
	Message: string,
	Signature: string
}

type X25519TestVector = {
	Description: string,
	SecretKey: string,
	PublicKey: string,
	Expected: string
}

type InvalidTestVector = {
	TestName: string,
	Pubkey: string,
	Msg: string,
	Signature: string,
}

type X25519 = {
	Secret: string,
	CounterKey: string,
	K: string
}

type SmallOrderInputs = {
	Input: string,
	Expected: string,
}

type InvalidPublicKeys = { Key: string }

local Algorithm = require("../Verification/EdDSA")
local MaskedX25519 = Algorithm.MaskedX25519
local CSPRNG = Algorithm.CSPRNG

local function FromHex(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	for Index = 0, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end

	return Buffer
end

local function ToHex(Buffer: buffer): string
	local Hex = ""
	for Index = 0, buffer.len(Buffer) - 1 do
		Hex ..= string.format("%02x", buffer.readu8(Buffer, Index))
	end

	return Hex
end

local function IsValidX25519Key(Key: buffer): (boolean, string)
	if buffer.len(Key) ~= 32 then
		return false, "Key must be exactly 32 bytes"
	end

	local FirstByte = buffer.readu8(Key, 0)
	local LastByte = buffer.readu8(Key, 31)

	if bit32.band(FirstByte, 0x07) ~= 0 then
		return false, "First byte must have lowest 3 bits set to 0 (X25519 clamping)"
	end

	if bit32.band(LastByte, 0x80) ~= 0 then
		return false, "Last byte must have highest bit set to 0 (X25519 clamping)"
	end

	if bit32.band(LastByte, 0x40) == 0 then
		return false, "Last byte must have second highest bit set to 1 (X25519 clamping)"
	end

	local AllZeros = true
	local AllOnes = true

	for I = 0, 31 do
		local Byte = buffer.readu8(Key, I)
		if Byte ~= 0 then
			AllZeros = false
		end
		if Byte ~= 255 then
			AllOnes = false
		end
	end

	if AllZeros then
		return false, "Key cannot be all zeros (weak key)"
	end

	if AllOnes then
		return false, "Key cannot be all ones (weak key)"
	end

	local IsIdentity = true
	if buffer.readu8(Key, 0) ~= 1 then
		IsIdentity = false
	else
		for I = 1, 31 do
			if buffer.readu8(Key, I) ~= 0 then
				IsIdentity = false
				break
			end
		end
	end

	if IsIdentity then
		return false, "Key cannot be the identity element"
	end

	return true, "Valid X25519 key"
end

local function Exchange(SecretKey: buffer, PublicKey: buffer): buffer
	local MaskedSecretKey = MaskedX25519.Mask(SecretKey)
	MaskedSecretKey = MaskedX25519.Remask(MaskedSecretKey)
	local SharedSecret = MaskedX25519.Exchange(MaskedSecretKey, PublicKey)

	return SharedSecret
end

local WycheproofVectors: {Wycheproof} = {
	{
		TestName = "NORMAL CASE",
		Secret = "4852834d9d6b77dadeabaaf2e11dca66d19fe74993a7bec36c6e16a0983feaba",
		CounterKey = "9c647d9ae589b9f58fdc3ca4947efbc915c4b2e08e744a0edf469dac59c8f85a",
		K = "87b7f212b627f7a54ca5e0bcdaddd5389d9de6156cdbcf8ebe14ffbcfb436551",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY ON TWIST 1",
		Secret = "588c061a50804ac488ad774ac716c3f5ba714b2712e048491379a500211998a8",
		CounterKey = "63aa40c6e38346c5caf23a6df0a5e6c80889a08647e551b3563449befcfc9733",
		K = "b1a707519495ffffb298ff941716b06dfab87cf8d91123fe2be9a233dda22212",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY ON TWIST 2",
		Secret = "b05bfd32e55325d9fd648cb302848039000b390e44d521e58aab3b29a6960ba8",
		CounterKey = "0f83c36fded9d32fadf4efa3ae93a90bb5cfa66893bc412c43fa7287dbb99779",
		K = "67dd4a6e165533534c0e3f172e4ab8576bca923a5f07b2c069b4c310ff2e935b",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY ON TWIST 3",
		Secret = "70e34bcbe1f47fbc0fddfd7c1e1aa53d57bfe0f66d243067b424bb6210bed19c",
		CounterKey = "0b8211a2b6049097f6871c6c052d3c5fc1ba17da9e32ae458403b05bb283092a",
		K = "4a0638cfaa9ef1933b47f8939296a6b25be541ef7f70e844c0bcc00b134de64a",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY ON TWIST 4",
		Secret = "68c1f3a653a4cdb1d37bba94738f8b957a57beb24d646e994dc29a276aad458d",
		CounterKey = "343ac20a3b9c6a27b1008176509ad30735856ec1c8d8fcae13912d08d152f46c",
		K = "399491fce8dfab73b4f9f611de8ea0b27b28f85994250b0f475d585d042ac207",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY ON TWIST 5",
		Secret = "d877b26d06dff9d9f7fd4c5b3769f8cdd5b30516a5ab806be324ff3eb69ea0b2",
		CounterKey = "fa695fc7be8d1be5bf704898f388c452bafdd3b8eae805f8681a8d15c2d4e142",
		K = "2c4fe11d490a53861776b13b4354abd4cf5a97699db6e6c68c1626d07662f758",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY ZERO",
		Secret = "207494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd4debc",
		CounterKey = "0000000000000000000000000000000000000000000000000000000000000000",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY ONE",
		Secret = "202e8972b61c7e61930eb9450b5070eae1c670475685541f0476217e4818cfab",
		CounterKey = "0100000000000000000000000000000000000000000000000000000000000000",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "EDGE CASE ON TWIST 1",
		Secret = "38dde9f3e7b799045f9ac3793d4a9277dadeadc41bec0290f81f744f73775f84",
		CounterKey = "0200000000000000000000000000000000000000000000000000000000000000",
		K = "9a2cfe84ff9c4a9739625cae4a3b82a906877a441946f8d7b3d795fe8f5d1639",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE ON TWIST 2",
		Secret = "9857a914e3c29036fd9a442ba526b5cdcdf28216153e636c10677acab6bd6aa5",
		CounterKey = "0300000000000000000000000000000000000000000000000000000000000000",
		K = "4da4e0aa072c232ee2f0fa4e519ae50b52c1edd08a534d4ef346c2e106d21d60",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE ON TWIST 3",
		Secret = "48e2130d723305ed05e6e5894d398a5e33367a8c6aac8fcdf0a88e4b42820db7",
		CounterKey = "ffffff030000f8ffff1f0000c0ffffff000000feffff070000f0ffff3f000000",
		K = "9ed10c53747f647f82f45125d3de15a1e6b824496ab40410ffcc3cfe95760f3b",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE ON TWIST 4",
		Secret = "28f41011691851b3a62b641553b30d0dfddcb8fffcf53700a7be2f6a872e9fb0",
		CounterKey = "000000fcffff070000e0ffff3f000000ffffff010000f8ffff0f0000c0ffff7f",
		K = "cf72b4aa6aa1c9f894f4165b86109aa468517648e1f0cc70e1ab08460176506b",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE ON TWIST 5",
		Secret = "18a93b6499b9f6b3225ca02fef410e0adec23532321d2d8ef1a6d602a8c65b83",
		CounterKey = "00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffff7f",
		K = "5d50b62836bb69579410386cf7bb811c14bf85b1c7b17e5924c7ffea91ef9e12",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE ON TWIST 6",
		Secret = "c01d1305a1338a1fcac2ba7e2e032b427e0b04903165aca957d8d0553d8717b0",
		CounterKey = "eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		K = "19230eb148d5d67c3c22ab1daeff80a57eae4265ce2872657b2c8099fc698e50",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE PUBLIC KEY 1",
		Secret = "386f7f16c50731d64f82e6a170b142a4e34f31fd7768fcb8902925e7d1e21abe",
		CounterKey = "0400000000000000000000000000000000000000000000000000000000000000",
		K = "0fcab5d842a078d7a71fc59b57bfb4ca0be6873b49dcdb9f44e14ae8fbdfa542",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE PUBLIC KEY 2",
		Secret = "e023a289bd5e90fa2804ddc019a05ef3e79d434bb6ea2f522ecb643a75296e95",
		CounterKey = "ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000",
		K = "54ce8f2275c077e3b1306a3939c5e03eef6bbb88060544758d9fef59b0bc3e4f",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE PUBLIC KEY 3",
		Secret = "68f010d62ee8d926053a361c3a75c6ea4ebdc8606ab285003a6f8f4076b01e83",
		CounterKey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03",
		K = "f136775c5beb0af8110af10b20372332043cab752419678775a223df57c9d30d",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE PUBLIC KEY 4",
		Secret = "58ebcb35b0f8845caf1ec630f96576b62c4b7b6c36b29deb2cb0084651755c96",
		CounterKey = "fffffffbfffffbffffdfffffdffffffffefffffefffff7fffff7ffffbfffff3f",
		K = "bf9affd06b844085586460962ef2146ff3d4533d9444aab006eb88cc3054407d",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE PUBLIC KEY 5",
		Secret = "188c4bc5b9c44b38bb658b9b2ae82d5b01015e093184b17cb7863503a783e1bb",
		CounterKey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
		K = "d480de04f699cb3be0684a9cc2e31281ea0bc5a9dcc157d3d20158d46ca5246d",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE PUBLIC KEY 6",
		Secret = "e06c11bb2e13ce3dc7673f67f5482242909423a9ae95ee986a988d98faee23a2",
		CounterKey = "fffffffffeffff7ffffffffffeffff7ffffffffffeffff7ffffffffffeffff7f",
		K = "4c4401cce6b51e4cb18f2790246c9bf914db667750a1cb89069092af07292276",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE PUBLIC KEY 7",
		Secret = "c0658c46dde18129293877535b1162b6f9f5414a23cf4d2cbc140a4d99da2b8f",
		CounterKey = "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		K = "578ba8cc2dbdc575afcf9df2b3ee6189f5337d6854c79b4ce165ea12293b3a0f",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 1",
		Secret = "10255c9230a97a30a458ca284a629669293a31890cda9d147febc7d1e22d6bb1",
		CounterKey = "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 2",
		Secret = "78f1e8edf14481b389448dac8f59c70b038e7cf92ef2c7eff57a72466e115296",
		CounterKey = "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 3",
		Secret = "a0a05a3e8f9f44204d5f8059a94ac7dfc39a49ac016dd743dbfa43c5d671fd88",
		CounterKey = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 4",
		Secret = "d0dbb3ed1906663f15420af31f4eaf6509d9a9949723500605ad7c1c6e7450a9",
		CounterKey = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 5",
		Secret = "c0b1d0eb22b244fe3291140072cdd9d989b5f0ecd96c100feb5bca241c1d9f8f",
		CounterKey = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 6",
		Secret = "480bf45f594942a8bc0f3353c6e8b8853d77f351f1c2ca6c2d1abf8a00b4229c",
		CounterKey = "0000000000000000000000000000000000000000000000000000000000000080",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 7",
		Secret = "30f993fcf8514fc89bd8db14cd43ba0d4b2530e73c4276a05e1b145d420cedb4",
		CounterKey = "0100000000000000000000000000000000000000000000000000000000000080",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 8",
		Secret = "c04974b758380e2a5b5df6eb09bb2f6b3434f982722a8e676d3da251d1b3de83",
		CounterKey = "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 9",
		Secret = "502a31373db32446842fe5add3e024022ea54f274182afc3d9f1bb3d39534eb5",
		CounterKey = "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 10",
		Secret = "90fa6417b0e37030fd6e43eff2abaef14c6793117a039cf621318ba90f4e98be",
		CounterKey = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 11",
		Secret = "78ad3f26027f1c9fdd975a1613b947779bad2cf2b741ade01840885a30bb979c",
		CounterKey = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY LOW ORDER 12",
		Secret = "98e23de7b1e0926ed9c87e7b14baf55f497a1d7096f93977680e44dc1c7b7b8b",
		CounterKey = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		K = "0000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = true
	},
	{
		TestName = "PUBLIC KEY GE P 1",
		Secret = "f01e48dafac9d7bcf589cbc382c878d18bda3550589ffb5d50b523bebe329dae",
		CounterKey = "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		K = "bd36a0790eb883098c988b21786773de0b3a4df162282cf110de18dd484ce74b",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY GE P 2",
		Secret = "288796bc5aff4b81a37501757bc0753a3c21964790d38699308debc17a6eaf8d",
		CounterKey = "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		K = "b4e0dd76da7b071728b61f856771aa356e57eda78a5b1655cc3820fb5f854c5c",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY GE P 3",
		Secret = "98df845f6651bf1138221f119041f72b6dbc3c4ace7143d99fd55ad867480da8",
		CounterKey = "f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		K = "6fdf6c37611dbd5304dc0f2eb7c9517eb3c50e12fd050ac6dec27071d4bfc034",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY GE P 4",
		Secret = "f09498e46f02f878829e78b803d316a2ed695d0498a08abdf8276930e24edcb0",
		CounterKey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		K = "4c8fc4b1c6ab88fb21f18f6d4c810240d4e94651ba44f7a2c863cec7dc56602d",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY GE P 5",
		Secret = "1813c10a5c7f21f96e17f288c0cc37607c04c5f5aea2db134f9e2ffc66bd9db8",
		CounterKey = "0200000000000000000000000000000000000000000000000000000000000080",
		K = "1cd0b28267dc541c642d6d7dca44a8b38a63736eef5c4e6501ffbbb1780c033c",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY GE P 6",
		Secret = "7857fb808653645a0beb138a64f5f4d733a45ea84c3cda11a9c06f7e7139149e",
		CounterKey = "0300000000000000000000000000000000000000000000000000000000000080",
		K = "8755be01c60a7e825cff3e0e78cb3aa4333861516aa59b1c51a8b2a543dfa822",
		ShouldFail = false
	},
	{
		TestName = "PUBLIC KEY GE P 7",
		Secret = "e03aa842e2abc56e81e87b8b9f417b2a1e5913c723eed28d752f8d47a59f498f",
		CounterKey = "0400000000000000000000000000000000000000000000000000000000000080",
		K = "54c9a1ed95e546d27822a360931dda60a1df049da6f904253c0612bbdc087476",
		ShouldFail = false
	},
	{
		TestName = "RFC 7748 TEST 1",
		Secret = "a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44",
		CounterKey = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
		K = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
		ShouldFail = false
	},
	{
		TestName = "RFC 7748 TEST 2",
		Secret = "4866e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d",
		CounterKey = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413",
		K = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE SHARED SECRET 1",
		Secret = "a0a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a976bf63",
		CounterKey = "0ab4e76380d84dde4f6833c58f2a9fb8f83bb0169b172be4b6e0592887741a36",
		K = "0200000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE SHARED SECRET 2",
		Secret = "a0a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a976bf63",
		CounterKey = "89e10d5701b4337d2d032181538b1064bd4084401ceca1fd12663a1959388000",
		K = "0900000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = false
	},
	{
		TestName = "EDGE CASE SHARED SECRET 3",
		Secret = "a0a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a976bf63",
		CounterKey = "2b55d3aa4a8f80c8c0b2ae5f933e85af49beac36c2fa7394bab76c8933f8f81d",
		K = "1000000000000000000000000000000000000000000000000000000000000000",
		ShouldFail = false
	},
	{
		TestName = "CHECKING OVERFLOW 1",
		Secret = "c81724704000b26d31703cc97e3a378d56fad8219361c88cca8bd7c5719b12b2",
		CounterKey = "fd300aeb40e1fa582518412b49b208a7842b1e1f056a040178ea4141534f652d",
		K = "b734105dc257585d73b566ccb76f062795ccbec89128e52b02f3e59639f13c46",
		ShouldFail = false
	},
	{
		TestName = "CHECKING OVERFLOW 2",
		Secret = "c81724704000b26d31703cc97e3a378d56fad8219361c88cca8bd7c5719b12b2",
		CounterKey = "c8ef79b514d7682677bc7931e06ee5c27c9b392b4ae9484473f554e6678ecc2e",
		K = "647a46b6fc3f40d62141ee3cee706b4d7a9271593a7b143e8e2e2279883e4550",
		ShouldFail = false
	},
	{
		TestName = "CHECKING OVERFLOW 3",
		Secret = "c81724704000b26d31703cc97e3a378d56fad8219361c88cca8bd7c5719b12b2",
		CounterKey = "64aeac2504144861532b7bbcb6c87d67dd4c1f07ebc2e06effb95aecc6170b2c",
		K = "4ff03d5fb43cd8657a3cf37c138cadcecce509e4eba089d0ef40b4e4fb946155",
		ShouldFail = false
	},
	{
		TestName = "PRIVATE KEY MOD ORDER",
		Secret = "a023cdd083ef5bb82f10d62e59e15a6800000000000000000000000000000050",
		CounterKey = "258e04523b8d253ee65719fc6906c657192d80717edc828fa0af21686e2faa75",
		K = "258e04523b8d253ee65719fc6906c657192d80717edc828fa0af21686e2faa75",
		ShouldFail = false
	},
	{
		TestName = "LIBSODIUM SCALARMULT 1",
		Secret = "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
		CounterKey = "0900000000000000000000000000000000000000000000000000000000000000",
		K = "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A",
		ShouldFail = false
	},
	{
		TestName = "LIBSODIUM SCALARMULT 2",
		Secret = "5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB",
		CounterKey = "0900000000000000000000000000000000000000000000000000000000000000",
		K = "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F",
		ShouldFail = false
	},
	{
		TestName = "LIBSODIUM SCALARMULT 5",
		Secret = "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
		CounterKey = "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F",
		K = "4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742",
		ShouldFail = false
	},
	{
		TestName = "LIBSODIUM SCALARMULT 6",
		Secret = "5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB",
		CounterKey = "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A",
		K = "4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742",
		ShouldFail = false
	},
	{
		TestName = "DONNA TEST NONCANON 1",
		Secret = "0100000000000000000000000000000000000000000000000000000000000000",
		CounterKey = "2500000000000000000000000000000000000000000000000000000000000000",
		K = "3C7777CAF997B264416077665B4E229D0B9548DC0CD81998DDCDC5C8533C797F",
		ShouldFail = false
	},
	{
		TestName = "DONNA TEST NONCANON 2",
		Secret = "0100000000000000000000000000000000000000000000000000000000000000",
		CounterKey = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		K = "B32D1362C248D62FE62619CFF04DD43DB73FFC1B6308EDE30B78D87380F1E834",
		ShouldFail = false
	},
	{
		TestName = "DONNA RANDOM 1",
		Secret = "D55FF01DA1262795A4E50E607F87B80DCCD447A6EE0F6CD8D25177F79575744D",
		CounterKey = "0900000000000000000000000000000000000000000000000000000000000000",
		K = "D5BDC7055ABA7855692CC861009E3AE6B6339329826B11F8B92E5ADAEB85335E",
		ShouldFail = false
	},
	{
		TestName = "DONNA RANDOM 2",
		Secret = "0224D9367436089D81B1150DFC748EC851F9A41389E21C8C1181E01BA1760C23",
		CounterKey = "0900000000000000000000000000000000000000000000000000000000000000",
		K = "AD7E1E41C6AC0544F949EB76D71C75120ADD345C44384BDD830974D2DD329644",
		ShouldFail = false
	},
	{
		TestName = "DONNA CROSS TEST 1",
		Secret = "D55FF01DA1262795A4E50E607F87B80DCCD447A6EE0F6CD8D25177F79575744D",
		CounterKey = "AD7E1E41C6AC0544F949EB76D71C75120ADD345C44384BDD830974D2DD329644",
		K = "FC343E1965225D8666F4AE8E70E04039D21C603F7CE7F17C0CC8440C62C03575",
		ShouldFail = false
	},
	{
		TestName = "DONNA CROSS TEST 2",
		Secret = "0224D9367436089D81B1150DFC748EC851F9A41389E21C8C1181E01BA1760C23",
		CounterKey = "D5BDC7055ABA7855692CC861009E3AE6B6339329826B11F8B92E5ADAEB85335E",
		K = "FC343E1965225D8666F4AE8E70E04039D21C603F7CE7F17C0CC8440C62C03575",
		ShouldFail = false
	}
}

local InvalidTestVectors: {InvalidTestVector} = {
	{
		TestName = "OSS-Fuzz #7156",
		Pubkey = "29A5670182010000000000002007643AE1720EF35AA223252F021A68F707511A",
		Msg = "30820143A0030201020209009C28A1A9B4502044300506032B65703045310B30090603550406130241553113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C7464301E170D3134303432333233323135375A170D3134303532333233323135375A3045310B30090603550406130241553113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C7464302A300506032B657003210029A5670182010000000000002007643AE1720EF35AA223252F021A68F707511AA350304E301D060362E3E704160414A29B7B795F9F24ADAFDDA87A40F526963D7FFBB5301F0603555F2304183016821421EC7B795F9F1F000000A87AC0F53D7FB5963FFB300C0603551DAA040530030101FF",
		Signature = "6EFA4FC58BA3BCF7C51598710C8D7182857E28C06D8C310BB5090603550406132020202020202020202020202020202020202020202020202020202020202016",
	},
	{
		TestName = "Special values r=0, s=0",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "3f",
		Signature = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		TestName = "Special values r=0, s=1",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "3f",
		Signature = "00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000",
	},
	{
		TestName = "Special values r=0, s=order-1",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "3f",
		Signature = "0000000000000000000000000000000000000000000000000000000000000000ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
	},
	{
		TestName = "Special values r=0, s=order",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "3f",
		Signature = "0000000000000000000000000000000000000000000000000000000000000000edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
	},
	{
		TestName = "Special values r=0, s=2^255-1",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "3f",
		Signature = "0000000000000000000000000000000000000000000000000000000000000000edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	},
	{
		TestName = "Empty signature",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "54657374",
		Signature = "",
	},
	{
		TestName = "Signature missing s component",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "54657374",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0",
	},
	{
		TestName = "Signature too short by 1 byte",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "54657374",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946",
	},
	{
		TestName = "Signature too long by 1 byte",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "54657374",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d2020",
	},
	{
		TestName = "Malleability test - s > order",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "54657374",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	},
	{
		TestName = "Modified bit 0 in R",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "647c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2b1d125e5538f38afbcc1c84e489521083041d24bc6240767029da063271a1ff0c",
	},
	{
		TestName = "Modified bit 255 in R",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281cab227aedf259f910f0f3a759a335062665217925d019173b88917eae294f75d40f",
	},
	{
		TestName = "R equals zero",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "0000000000000000000000000000000000000000000000000000000000000000e0b8e7770d51c7a36375d006c5bffd6af43ff54aaf47e4330dc118c71d61ec02",
	},
	{
		TestName = "Invalid R - all bits set",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff463a1908382e7eb7693acef9884f7cf931a215e0791876be22c631a59881fd0e",
	},
	{
		TestName = "All bits flipped in R",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "9a83eb6dbfd54a31fc1d3c580fc7b2fae4630ca8f0edf803873e433673d7e3d40e94254586cb6188c5386c3febed477cb9a6cb29e3979adc4cb27cf5278fb70a",
	},
	{
		TestName = "Malleability test - s > order (1)",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "54657374",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab067654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d",
	},
	{
		TestName = "Malleability test (2)",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab05439412b5395d42f462c67008eba6ca839d4eef676573336a5c51eb6f946b32d",
	},
	{
		TestName = "Malleability test (3)",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab02ee12ce5875bf9dff26556464bae2ad239d4eef676573336a5c51eb6f946b34d",
	},
	{
		TestName = "Malleability test (4)",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0e2300459f1e742404cd934d2c595a6253ad4eef676573336a5c51eb6f946b38d",
	},
	{
		TestName = "Malleability test (5)",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b32d",
	},
	{
		TestName = "Malleability test (6)",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b34d",
	},
	{
		TestName = "Malleability test (7)",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b38d",
	},
	{
		TestName = "Malleability test (8)",
		Pubkey = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
		Msg = "313233343030",
		Signature = "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0679155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b38d",
	},
}

local X25519TestVectors: {X25519TestVector} = {
	{
		Description = "RFC 7748 Test Vector 1",
		SecretKey = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
		PublicKey = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
		Expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
	},
	{
		Description = "RFC 7748 Test Vector 2 Invalid Point",
		SecretKey = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
		PublicKey = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
		Expected = "Invalid public key"
	},
	{
		Description = "RFC 7748 Iteration 1",
		SecretKey = "0900000000000000000000000000000000000000000000000000000000000000",
		PublicKey = "0900000000000000000000000000000000000000000000000000000000000000",
		Expected = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
	},
	{
		Description = "Zero Input Invalid Point",
		SecretKey = "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff",
		PublicKey = "0000000000000000000000000000000000000000000000000000000000000000",
		Expected = "Invalid public key"
	},
	{
		Description = "One Input Invalid Point",
		SecretKey = "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff",
		PublicKey = "0100000000000000000000000000000000000000000000000000000000000000",
		Expected = "Invalid public key"
	},
	{
		Description = "Non-Zero Result",
		SecretKey = "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff",
		PublicKey = "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
		Expected = "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175"
	}
}

local TestVectors: {X25519} = {
	{
		Secret = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
		CounterKey = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
		K = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	},
	{
		Secret = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
		CounterKey = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
		K = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	},
	{
		Secret = "0000000000000000000000000000000000000000000000000000000000000000",
		CounterKey = "0000000000000000000000000000000000000000000000000000000000000000",
		K = "0000000000000000000000000000000000000000000000000000000000000000"
	}
}

local SmallOrderInputs: {SmallOrderInputs} = {
	{ Input = "0000000000000000000000000000000000000000000000000000000000000000", Expected = "Invalid public key" },
	{ Input = "0100000000000000000000000000000000000000000000000000000000000000", Expected = "Invalid public key" },
	{ Input = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", Expected = "Invalid public key" },
	{ Input = "0000000000000000000000000000000000000000000000000000000000000080", Expected = "Invalid public key" }
}

local InvalidPublicKeys: {InvalidPublicKeys} = {
	{Key = "0000000000000000000000000000000000000000000000000000000000000000"},
	{Key = "0100000000000000000000000000000000000000000000000000000000000000"},
	{Key = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{Key = "0000000000000000000000000000000000000000000000000000000000000080"}
}

local Ed25519TestVectors: {Ed25519TestVector} = require("@self/Constants")
local Test = Testing.Test
local Expect = Testing.Expect

for Index, TestVector in Ed25519TestVectors do
	Test(`Ed25519 Public Key {Index}`, function()
		local PrivateKey = TestVector.PrivateKey
		local ExpectedPublicKey = TestVector.PublicKey

		local PrivateKeyBytes = FromHex(PrivateKey)
		local GeneratedPublicKeyBytes = Algorithm.PublicKey(PrivateKeyBytes)
		local GeneratedPublicKey = ToHex(GeneratedPublicKeyBytes)
		Expect(GeneratedPublicKey).ToBe(ExpectedPublicKey)
	end)
end

for Index, TestVector in Ed25519TestVectors do
	Test(`Ed25519 Sign {Index}`, function()
		local PrivateKey = TestVector.PrivateKey
		local PublicKey = TestVector.PublicKey
		local Message = TestVector.Message

		local PrivateKeyBytes = FromHex(PrivateKey)
		local PublicKeyBytes = FromHex(PublicKey)
		local MessageBytes = FromHex(Message)

		local GeneratedSignatureBytes = Algorithm.Sign(PrivateKeyBytes, PublicKeyBytes, MessageBytes)
		local IsValid = Algorithm.Verify(PublicKeyBytes, MessageBytes, GeneratedSignatureBytes)
		Expect(IsValid).ToBeTruthy()
	end)
end

for Index, TestVector in Ed25519TestVectors do
	Test(`Ed25519 Verify {Index}`, function()
		local PublicKey = TestVector.PublicKey
		local Message = TestVector.Message
		local Signature = TestVector.Signature

		local PublicKeyBytes = FromHex(PublicKey)
		local MessageBytes = FromHex(Message)
		local SignatureBytes = FromHex(Signature)
		local IsValid = Algorithm.Verify(PublicKeyBytes, MessageBytes, SignatureBytes)
		Expect(IsValid).ToBeTruthy()
	end)
end

for Index, TestVector in InvalidTestVectors do
	Test(`Ed25519 Invalid Test: {TestVector.TestName}`, function()
		local PublicKeyBytes = FromHex(TestVector.Pubkey)
		local MessageBytes = FromHex(TestVector.Msg)

		if TestVector.Signature == "" then
			local TestFunction = function()
				local SignatureBytes = buffer.create(0)
				Algorithm.Verify(PublicKeyBytes, MessageBytes, SignatureBytes)
			end
			Expect(TestFunction).ToThrow()

		elseif #TestVector.Signature ~= 128 then
			local TestFunction = function()
				local SignatureBytes = FromHex(TestVector.Signature)
				Algorithm.Verify(PublicKeyBytes, MessageBytes, SignatureBytes)
			end
			Expect(TestFunction).ToThrow()
		else
			local SignatureBytes = FromHex(TestVector.Signature)
			local IsValid = Algorithm.Verify(PublicKeyBytes, MessageBytes, SignatureBytes)
			Expect(IsValid).ToBeFalsy()
		end
	end)
end

Test("Ed25519 Signature High S Value Rejection", function()
	local PublicKeyBytes = FromHex("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")
	local MessageBytes = FromHex("54657374")

	local HighSSignature = FromHex("7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	local IsValid = Algorithm.Verify(PublicKeyBytes, MessageBytes, HighSSignature)
	Expect(IsValid).ToBeFalsy()

	local OrderSSignature = FromHex("7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	local IsValid2 = Algorithm.Verify(PublicKeyBytes, MessageBytes, OrderSSignature)
	Expect(IsValid2).ToBeFalsy()
end)

Test("Ed25519 Invalid Public Key Rejection", function()
	local MessageBytes = FromHex("54657374")
	local ValidSignature = FromHex("7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d")

	local InvalidPublicKey1 = FromHex("0000000000000000000000000000000000000000000000000000000000000000")
	local IsValid1 = Algorithm.Verify(InvalidPublicKey1, MessageBytes, ValidSignature)
	Expect(IsValid1).ToBeFalsy()

	local InvalidPublicKey2 = FromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	local IsValid2 = Algorithm.Verify(InvalidPublicKey2, MessageBytes, ValidSignature)
	Expect(IsValid2).ToBeFalsy()
end)

Test("Ed25519 Signature Bit Pattern Validation", function()
	local PublicKeyBytes = FromHex("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")
	local MessageBytes = FromHex("54657374")

	local InvalidSignature = FromHex("7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b3ff")
	local IsValid = Algorithm.Verify(PublicKeyBytes, MessageBytes, InvalidSignature)
	Expect(IsValid).ToBeFalsy()
end)

for Index, TestVector in X25519TestVectors do
	Test(`X25519 {TestVector.Description}`, function()
		local SecretKeyBytes = FromHex(TestVector.SecretKey)
		local PublicKeyBytes = FromHex(TestVector.PublicKey)

		if TestVector.Expected == "Invalid public key" then
			local TestFunction = function()
				Exchange(SecretKeyBytes, PublicKeyBytes)
			end
			Expect(TestFunction).ToThrow(TestVector.Expected)
		else
			local Result = Exchange(SecretKeyBytes, PublicKeyBytes)
			local ResultHex = ToHex(Result)
			Expect(ResultHex).ToBe(TestVector.Expected)
		end
	end)
end

Test("X25519 Iteration 1000", function()
	local K = FromHex("0900000000000000000000000000000000000000000000000000000000000000")
	local U = FromHex("0900000000000000000000000000000000000000000000000000000000000000")

	for I = 1, 1000 do
		local Result = Exchange(K, U)
		U = K
		K = Result
	end

	local Expected = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
	local ResultHex = ToHex(K)
	Expect(ResultHex).ToBe(Expected)
end)

Test("X25519 ECDH", function()
	local AlicePrivate = FromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	local AlicePublic = FromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

	local BobPrivate = FromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	local BobPublic = FromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

	local ExpectedShared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

	local AliceGeneratedPublic = MaskedX25519.PublicKey(MaskedX25519.Mask(AlicePrivate))
	Expect(ToHex(AliceGeneratedPublic)).ToBe(ToHex(AlicePublic))

	local BobGeneratedPublic = MaskedX25519.PublicKey(MaskedX25519.Mask(BobPrivate))
	Expect(ToHex(BobGeneratedPublic)).ToBe(ToHex(BobPublic))

	local AliceShared = Exchange(AlicePrivate, BobPublic)
	Expect(ToHex(AliceShared)).ToBe(ExpectedShared)

	local BobShared = Exchange(BobPrivate, AlicePublic)
	Expect(ToHex(BobShared)).ToBe(ExpectedShared)

	Expect(ToHex(AliceShared)).ToBe(ToHex(BobShared))
end)

Test("X25519 Base Point", function()
	local PeerPublicKey = FromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
	local Scalar = FromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	local SharedSecret = Exchange(Scalar, PeerPublicKey)

	Expect(ToHex(SharedSecret)).ToBe("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
end)

Test("X25519 Edge Cases", function()
	local SomeScalar = FromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")

	for _, TestCase in SmallOrderInputs do
		local Input = FromHex(TestCase.Input)
		local TestFunction = function()
			Exchange(SomeScalar, Input)
		end

		Expect(TestFunction).ToThrow(TestCase.Expected)
	end
end)

Test("X25519 Key Validation", function()
	local ValidCount = 0
	local InvalidCount = 0
	local InvalidReasons = {}

	for I = 1, 1000 do
		local GeneratedKey = CSPRNG.Ed25519Random()
		local IsValid, Message = IsValidX25519Key(GeneratedKey)

		if IsValid then
			ValidCount += 1
		else
			InvalidCount += 1
			if not InvalidReasons[Message] then
				InvalidReasons[Message] = 0
			end
			InvalidReasons[Message] += 1
		end
	end

	if InvalidCount > 0 then
		print("Invalid Key Reasons:")
		for Reason, Count in InvalidReasons do
			print(string.format("  %s: %d", Reason, Count))
		end
	end

	Expect(ValidCount).ToBe(1000)
	Expect(InvalidCount).ToBe(0)
end)

Test("X25519 Argreement", function()
	for Index, Vector in TestVectors do
		local SecretBytes = FromHex(Vector.Secret)
		local CounterKeyBytes = FromHex(Vector.CounterKey)
		local ExpectedK = Vector.K

		local AllZeros = true
		for J = 0, buffer.len(FromHex(ExpectedK)) - 1 do
			if buffer.readu8(FromHex(ExpectedK), J) ~= 0 then
				AllZeros = false
				break
			end
		end

		if AllZeros then
			local TestFunction = function()
				Exchange(SecretBytes, CounterKeyBytes)
			end
			Expect(TestFunction).ToThrow()
		else
			local Result = Exchange(SecretBytes, CounterKeyBytes)
			local ResultHex = ToHex(Result)
			Expect(ResultHex).ToBe(ExpectedK)
		end
	end
end)

Test("X25519 Roundtrip", function()
	for I = 1, 10 do
		local AlicePrivate = CSPRNG.Ed25519Random()
		local BobPrivate = CSPRNG.Ed25519Random()

		local AliceMasked = MaskedX25519.Mask(AlicePrivate)
		local BobMasked = MaskedX25519.Mask(BobPrivate)

		local AlicePublic = MaskedX25519.PublicKey(AliceMasked)
		local BobPublic = MaskedX25519.PublicKey(BobMasked)

		local AliceSharedPrimary, AliceSharedMask = MaskedX25519.Exchange(AliceMasked, BobPublic)
		local BobSharedPrimary, BobSharedMask = MaskedX25519.Exchange(BobMasked, AlicePublic)

		Expect(ToHex(AliceSharedPrimary)).ToBe(ToHex(BobSharedPrimary))
		Expect(ToHex(AliceSharedMask)).Never.ToBe(ToHex(BobSharedMask))
	end
end)

Test("X25519 Keygen", function()
	for I = 1, 100 do
		local PrivateKey = CSPRNG.Ed25519Random()
		local MaskedKey = MaskedX25519.Mask(PrivateKey)
		local PublicKey1 = MaskedX25519.PublicKey(MaskedKey)

		local RemaskedKey = MaskedX25519.Remask(MaskedKey)
		local PublicKey2 = MaskedX25519.PublicKey(RemaskedKey)

		Expect(ToHex(PublicKey1)).ToBe(ToHex(PublicKey2))
	end
end)

Test("X25519 Masking", function()
	local OriginalKey = CSPRNG.Ed25519Random()
	local MaskedKey1 = MaskedX25519.Mask(OriginalKey)
	local MaskedKey2 = MaskedX25519.Mask(OriginalKey)

	local PublicKey1 = MaskedX25519.PublicKey(MaskedKey1)
	local PublicKey2 = MaskedX25519.PublicKey(MaskedKey2)

	Expect(ToHex(PublicKey1)).ToBe(ToHex(PublicKey2))

	local MaskComponent1 = MaskedX25519.MaskComponent(MaskedKey1)
	local MaskComponent2 = MaskedX25519.MaskComponent(MaskedKey2)

	Expect(ToHex(MaskComponent1)).Never.ToBe(ToHex(MaskComponent2))
end)

Test("X25519 Sign Masking", function()
	local SignatureSecretKey = CSPRNG.Ed25519Random()
	local MaskedSignatureKey = MaskedX25519.MaskSignature(SignatureSecretKey)

	Expect(buffer.len(MaskedSignatureKey)).ToBe(64)

	local PublicKey = MaskedX25519.PublicKey(MaskedSignatureKey)
	Expect(buffer.len(PublicKey)).ToBe(32)
end)

Test("X25519 Invalid Inputs", function()
	local ValidMaskedKey = MaskedX25519.Mask(CSPRNG.Ed25519Random())

	for _, Table in InvalidPublicKeys do
		local TestFunction = function()
			MaskedX25519.Exchange(ValidMaskedKey, FromHex(Table.Key))
		end
		Expect(TestFunction).ToThrow()
	end
end)

Test("X25519 Wycheproof", function()
	for Index, Vector in WycheproofVectors do
		local SecretBytes = FromHex(Vector.Secret)
		local CounterKeyBytes = FromHex(Vector.CounterKey)
		local ExpectedK = Vector.K

		if Vector.ShouldFail then
			local TestFunction = function()
				local MaskedKey = MaskedX25519.Mask(SecretBytes)
				MaskedX25519.Exchange(MaskedKey, CounterKeyBytes)
			end
			Expect(TestFunction).ToThrow("Invalid public key")
		else
			local TestFunction = function()
				local MaskedKey = MaskedX25519.Mask(SecretBytes)
				local Result, _ = MaskedX25519.Exchange(MaskedKey, CounterKeyBytes)
				local ResultHex = ToHex(Result)
				Expect(ResultHex).ToBe(ExpectedK:lower())
			end
		end
	end
end)

Testing.Complete()

return 0
