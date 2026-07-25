--[=[
    Cryptography library: Base64

    Return type: buffer
    Example usage:
        local Input = buffer.fromstring("Hello World")
        local Encoded = Base64.Encode(Input)
        local Decoded = Base64.Decode(Encoded)
--]=]

--!strict
--!optimize 2
--!native

local PADDING_CHARACTER = 61
local ALPHABET_BYTES = buffer.create(64) do
    local Characters = {
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        43, 47
    }

    for Index = 1, 64 do
        buffer.writeu8(ALPHABET_BYTES, Index - 1, Characters[Index])
    end
end

local ENCODE_A, ENCODE_B = buffer.create(131072), buffer.create(131072) do
    for Byte0 = 0, 255 do
        local Sextet0 = bit32.rshift(Byte0, 2)
        local Sextet0Char = buffer.readu8(ALPHABET_BYTES, Sextet0)
        local Byte0Low = Byte0 % 4
        for Byte1 = 0, 255 do
            local Sextet1 = Byte0Low * 16 + (Byte1 // 16)
            local Index = (Byte0 + Byte1 * 256) * 2
            buffer.writeu16(ENCODE_A, Index, Sextet0Char + buffer.readu8(ALPHABET_BYTES, Sextet1) * 256)
        end
    end

    for Byte1 = 0, 255 do
        local Nibble = (Byte1 % 16) * 4
        for Byte2 = 0, 255 do
            local Sextet2 = Nibble + (Byte2 // 64)
            local Sextet3 = Byte2 % 64
            local Index = (Byte1 + Byte2 * 256) * 2
            buffer.writeu16(ENCODE_B, Index, buffer.readu8(ALPHABET_BYTES, Sextet2) + buffer.readu8(ALPHABET_BYTES, Sextet3) * 256)
        end
    end
end

local DECODE_TET = buffer.create(256) do
    for Index = 1, 64 do
        buffer.writeu8(DECODE_TET, buffer.readu8(ALPHABET_BYTES, Index - 1), Index - 1)
    end

    buffer.writeu8(DECODE_TET, PADDING_CHARACTER, 254)
end

local DECODE_PAIR = buffer.create(131072) do
    for Char0 = 0, 255 do
        local Decoded0 = buffer.readu8(DECODE_TET, Char0)
        for Char1 = 0, 255 do
            local Decoded1 = buffer.readu8(DECODE_TET, Char1)
            local Key = (Char0 + Char1 * 256) * 2
            if Decoded0 < 64 and Decoded1 < 64 then
                buffer.writeu16(DECODE_PAIR, Key, Decoded0 * 64 + Decoded1)
            elseif Decoded0 == 254 or Decoded1 == 254 then
                buffer.writeu16(DECODE_PAIR, Key, 254)
            end
        end
    end
end

local function Encode(Input: buffer): buffer
    local InputLength = buffer.len(Input)
    if InputLength == 0 then
        return buffer.create(0)
    end

    local Output = buffer.create(((InputLength + 2) // 3) * 4)
    local InputIndex = 0
    local OutputIndex = 0
    local FullTripletEnd = InputLength - (InputLength % 3)

    local EncodeA = ENCODE_A
    local EncodeB = ENCODE_B
    local AlphabetBytes = ALPHABET_BYTES

    local UnrollStop16 = InputLength - 49
    while InputIndex <= UnrollStop16 do
        local Word0 = buffer.readu32(Input, InputIndex + 0)
        local Word1 = buffer.readu32(Input, InputIndex + 3)
        local Word2 = buffer.readu32(Input, InputIndex + 6)
        local Word3 = buffer.readu32(Input, InputIndex + 9)
        local Word4 = buffer.readu32(Input, InputIndex + 12)
        local Word5 = buffer.readu32(Input, InputIndex + 15)
        local Word6 = buffer.readu32(Input, InputIndex + 18)
        local Word7 = buffer.readu32(Input, InputIndex + 21)
        local Word8 = buffer.readu32(Input, InputIndex + 24)
        local Word9 = buffer.readu32(Input, InputIndex + 27)
        local Word10 = buffer.readu32(Input, InputIndex + 30)
        local Word11 = buffer.readu32(Input, InputIndex + 33)
        local Word12 = buffer.readu32(Input, InputIndex + 36)
        local Word13 = buffer.readu32(Input, InputIndex + 39)
        local Word14 = buffer.readu32(Input, InputIndex + 42)
        local Word15 = buffer.readu32(Input, InputIndex + 45)
        buffer.writeu32(Output, OutputIndex + 0, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word0, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word0, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 4, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word1, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word1, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 8, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word2, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word2, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 12, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word3, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word3, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 16, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word4, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word4, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 20, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word5, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word5, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 24, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word6, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word6, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 28, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word7, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word7, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 32, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word8, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word8, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 36, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word9, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word9, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 40, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word10, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word10, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 44, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word11, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word11, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 48, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word12, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word12, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 52, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word13, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word13, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 56, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word14, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word14, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 60, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word15, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word15, 8), 0xFFFF), 1)), 16)))
        InputIndex += 48
        OutputIndex += 64
    end
    local UnrollStop4 = InputLength - 13
    while InputIndex <= UnrollStop4 do
        local Word0 = buffer.readu32(Input, InputIndex + 0)
        local Word1 = buffer.readu32(Input, InputIndex + 3)
        local Word2 = buffer.readu32(Input, InputIndex + 6)
        local Word3 = buffer.readu32(Input, InputIndex + 9)
        buffer.writeu32(Output, OutputIndex + 0, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word0, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word0, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 4, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word1, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word1, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 8, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word2, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word2, 8), 0xFFFF), 1)), 16)))
        buffer.writeu32(Output, OutputIndex + 12, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(bit32.band(Word3, 0xFFFF), 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(bit32.band(bit32.rshift(Word3, 8), 0xFFFF), 1)), 16)))
        InputIndex += 12
        OutputIndex += 16
    end
    while InputIndex < FullTripletEnd do
        local KeyA = buffer.readu16(Input, InputIndex)
        local Byte2 = buffer.readu8(Input, InputIndex + 2)
        local KeyB = bit32.bor(bit32.rshift(KeyA, 8), bit32.lshift(Byte2, 8))
        buffer.writeu32(Output, OutputIndex, bit32.bor(buffer.readu16(EncodeA, bit32.lshift(KeyA, 1)), bit32.lshift(buffer.readu16(EncodeB, bit32.lshift(KeyB, 1)), 16)))
        InputIndex += 3
        OutputIndex += 4
    end

    local Remainder = InputLength - InputIndex
    if Remainder == 1 then
        local Byte0 = buffer.readu8(Input, InputIndex)
        local Sextet0 = bit32.rshift(Byte0, 2)
        local Sextet1 = bit32.lshift(bit32.band(Byte0, 3), 4)
        local Pair = bit32.bor(buffer.readu8(AlphabetBytes, Sextet0), bit32.lshift(buffer.readu8(AlphabetBytes, Sextet1), 8))
        buffer.writeu16(Output, OutputIndex, Pair)
        buffer.writeu8(Output, OutputIndex + 2, PADDING_CHARACTER)
        buffer.writeu8(Output, OutputIndex + 3, PADDING_CHARACTER)
    elseif Remainder == 2 then
        local Byte0 = buffer.readu8(Input, InputIndex)
        local Byte1 = buffer.readu8(Input, InputIndex + 1)
        local KeyA = bit32.bor(Byte0, bit32.lshift(Byte1, 8))
        buffer.writeu16(Output, OutputIndex, buffer.readu16(EncodeA, bit32.lshift(KeyA, 1)))
        local Sextet2 = bit32.lshift(bit32.band(Byte1, 15), 2)
        buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(AlphabetBytes, Sextet2))
        buffer.writeu8(Output, OutputIndex + 3, PADDING_CHARACTER)
    end

    return Output
end

local function Decode(Input: buffer): buffer
    local InputLength = buffer.len(Input)
    if InputLength == 0 then
        return buffer.create(0)
    end

    if InputLength % 4 ~= 0 then
        error(`Base64 input length must be a multiple of 4, got {InputLength}`, 2)
    end

    local Padding = 0
    if buffer.readu8(Input, InputLength - 1) == PADDING_CHARACTER then
        Padding = 1
        if buffer.readu8(Input, InputLength - 2) == PADDING_CHARACTER then
            Padding = 2
        end
    end

    local Output = buffer.create((InputLength // 4) * 3 - Padding)
    local InputIndex = 0
    local OutputIndex = 0
    local BodyEnd = InputLength - 4

    local DecodePair = DECODE_PAIR
    local Dtet = DECODE_TET

    local UnrollStop16 = BodyEnd - 64
    while InputIndex <= UnrollStop16 do
        local Word0 = buffer.readu32(Input, InputIndex + 0)
        local Word1 = buffer.readu32(Input, InputIndex + 4)
        local Word2 = buffer.readu32(Input, InputIndex + 8)
        local Word3 = buffer.readu32(Input, InputIndex + 12)
        local Word4 = buffer.readu32(Input, InputIndex + 16)
        local Word5 = buffer.readu32(Input, InputIndex + 20)
        local Word6 = buffer.readu32(Input, InputIndex + 24)
        local Word7 = buffer.readu32(Input, InputIndex + 28)
        local Word8 = buffer.readu32(Input, InputIndex + 32)
        local Word9 = buffer.readu32(Input, InputIndex + 36)
        local Word10 = buffer.readu32(Input, InputIndex + 40)
        local Word11 = buffer.readu32(Input, InputIndex + 44)
        local Word12 = buffer.readu32(Input, InputIndex + 48)
        local Word13 = buffer.readu32(Input, InputIndex + 52)
        local Word14 = buffer.readu32(Input, InputIndex + 56)
        local Word15 = buffer.readu32(Input, InputIndex + 60)
        local PairA0 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word0, 0xFFFF), 1))
        local PairB0 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word0, 16), 1))
        buffer.writeu32(Output, OutputIndex + 0, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA0, 12), PairB0)), 8))
        local PairA1 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word1, 0xFFFF), 1))
        local PairB1 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word1, 16), 1))
        buffer.writeu32(Output, OutputIndex + 3, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA1, 12), PairB1)), 8))
        local PairA2 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word2, 0xFFFF), 1))
        local PairB2 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word2, 16), 1))
        buffer.writeu32(Output, OutputIndex + 6, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA2, 12), PairB2)), 8))
        local PairA3 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word3, 0xFFFF), 1))
        local PairB3 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word3, 16), 1))
        buffer.writeu32(Output, OutputIndex + 9, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA3, 12), PairB3)), 8))
        local PairA4 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word4, 0xFFFF), 1))
        local PairB4 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word4, 16), 1))
        buffer.writeu32(Output, OutputIndex + 12, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA4, 12), PairB4)), 8))
        local PairA5 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word5, 0xFFFF), 1))
        local PairB5 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word5, 16), 1))
        buffer.writeu32(Output, OutputIndex + 15, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA5, 12), PairB5)), 8))
        local PairA6 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word6, 0xFFFF), 1))
        local PairB6 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word6, 16), 1))
        buffer.writeu32(Output, OutputIndex + 18, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA6, 12), PairB6)), 8))
        local PairA7 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word7, 0xFFFF), 1))
        local PairB7 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word7, 16), 1))
        buffer.writeu32(Output, OutputIndex + 21, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA7, 12), PairB7)), 8))
        local PairA8 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word8, 0xFFFF), 1))
        local PairB8 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word8, 16), 1))
        buffer.writeu32(Output, OutputIndex + 24, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA8, 12), PairB8)), 8))
        local PairA9 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word9, 0xFFFF), 1))
        local PairB9 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word9, 16), 1))
        buffer.writeu32(Output, OutputIndex + 27, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA9, 12), PairB9)), 8))
        local PairA10 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word10, 0xFFFF), 1))
        local PairB10 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word10, 16), 1))
        buffer.writeu32(Output, OutputIndex + 30, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA10, 12), PairB10)), 8))
        local PairA11 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word11, 0xFFFF), 1))
        local PairB11 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word11, 16), 1))
        buffer.writeu32(Output, OutputIndex + 33, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA11, 12), PairB11)), 8))
        local PairA12 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word12, 0xFFFF), 1))
        local PairB12 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word12, 16), 1))
        buffer.writeu32(Output, OutputIndex + 36, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA12, 12), PairB12)), 8))
        local PairA13 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word13, 0xFFFF), 1))
        local PairB13 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word13, 16), 1))
        buffer.writeu32(Output, OutputIndex + 39, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA13, 12), PairB13)), 8))
        local PairA14 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word14, 0xFFFF), 1))
        local PairB14 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word14, 16), 1))
        buffer.writeu32(Output, OutputIndex + 42, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA14, 12), PairB14)), 8))
        local PairA15 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word15, 0xFFFF), 1))
        local PairB15 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word15, 16), 1))
        buffer.writeu32(Output, OutputIndex + 45, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA15, 12), PairB15)), 8))
        InputIndex += 64
        OutputIndex += 48
    end
    local UnrollStop4 = BodyEnd - 16
    while InputIndex <= UnrollStop4 do
        local Word0 = buffer.readu32(Input, InputIndex + 0)
        local Word1 = buffer.readu32(Input, InputIndex + 4)
        local Word2 = buffer.readu32(Input, InputIndex + 8)
        local Word3 = buffer.readu32(Input, InputIndex + 12)
        local PairA0 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word0, 0xFFFF), 1))
        local PairB0 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word0, 16), 1))
        buffer.writeu32(Output, OutputIndex + 0, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA0, 12), PairB0)), 8))
        local PairA1 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word1, 0xFFFF), 1))
        local PairB1 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word1, 16), 1))
        buffer.writeu32(Output, OutputIndex + 3, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA1, 12), PairB1)), 8))
        local PairA2 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word2, 0xFFFF), 1))
        local PairB2 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word2, 16), 1))
        buffer.writeu32(Output, OutputIndex + 6, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA2, 12), PairB2)), 8))
        local PairA3 = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word3, 0xFFFF), 1))
        local PairB3 = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word3, 16), 1))
        buffer.writeu32(Output, OutputIndex + 9, bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA3, 12), PairB3)), 8))
        InputIndex += 16
        OutputIndex += 12
    end
    while InputIndex <= BodyEnd - 4 do
        local Word = buffer.readu32(Input, InputIndex)
        local PairA = buffer.readu16(DecodePair, bit32.lshift(bit32.band(Word, 0xFFFF), 1))
        local PairB = buffer.readu16(DecodePair, bit32.lshift(bit32.rshift(Word, 16), 1))
        local Triple = bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(PairA, 12), PairB)), 8)
        buffer.writeu16(Output, OutputIndex, Triple)
        buffer.writeu8(Output, OutputIndex + 2, bit32.rshift(Triple, 16))
        InputIndex += 4
        OutputIndex += 3
    end

    local Char0 = buffer.readu8(Input, InputIndex)
    local Char1 = buffer.readu8(Input, InputIndex + 1)
    local Char2 = buffer.readu8(Input, InputIndex + 2)
    local Char3 = buffer.readu8(Input, InputIndex + 3)
    local Decoded0 = buffer.readu8(Dtet, Char0)
    local Decoded1 = buffer.readu8(Dtet, Char1)

    if Char2 == PADDING_CHARACTER then
        buffer.writeu8(Output, OutputIndex, bit32.bor(bit32.lshift(Decoded0, 2), bit32.rshift(Decoded1, 4)))
    elseif Char3 == PADDING_CHARACTER then
        local Decoded2 = buffer.readu8(Dtet, Char2)
        buffer.writeu8(Output, OutputIndex, bit32.bor(bit32.lshift(Decoded0, 2), bit32.rshift(Decoded1, 4)))
        buffer.writeu8(Output, OutputIndex + 1, bit32.bor(bit32.lshift(bit32.band(Decoded1, 15), 4), bit32.rshift(Decoded2, 2)))
    else
        local Decoded2 = buffer.readu8(Dtet, Char2)
        local Decoded3 = buffer.readu8(Dtet, Char3)
        local Triple = bit32.rshift(bit32.byteswap(bit32.bor(bit32.lshift(Decoded0, 18), bit32.lshift(Decoded1, 12), bit32.lshift(Decoded2, 6), Decoded3)), 8)
        buffer.writeu16(Output, OutputIndex, Triple)
        buffer.writeu8(Output, OutputIndex + 2, bit32.rshift(Triple, 16))
    end

    return Output
end

return {
    Encode = Encode,
    Decode = Decode
}
