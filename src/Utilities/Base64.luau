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

local ENCODE_SEXTET_PAIR = buffer.create(8192) do
    for Value = 0, 4095 do
        local High = buffer.readu8(ALPHABET_BYTES, bit32.rshift(Value, 6))
        local Low = buffer.readu8(ALPHABET_BYTES, bit32.band(Value, 63))
        buffer.writeu16(ENCODE_SEXTET_PAIR, Value * 2, bit32.bor(High, bit32.lshift(Low, 8)))
    end
end
local ENCODE_SEXTET_PAIR_SHIFTED = buffer.create(16384) do
    for Value = 0, 4095 do
        buffer.writeu32(ENCODE_SEXTET_PAIR_SHIFTED, Value * 4,
            bit32.lshift(buffer.readu16(ENCODE_SEXTET_PAIR, Value * 2), 16))
    end
end

local DECODE_TET = buffer.create(256) do
    for Index = 1, 64 do
        buffer.writeu8(DECODE_TET, buffer.readu8(ALPHABET_BYTES, Index - 1), Index - 1)
    end

    buffer.writeu8(DECODE_TET, PADDING_CHARACTER, 254)
end

local DECODE_PAIR_A = buffer.create(131072)
local DECODE_PAIR_B = buffer.create(131072) do
    for Char0 = 0, 255 do
        local Decoded0 = buffer.readu8(DECODE_TET, Char0)
        for Char1 = 0, 255 do
            local Decoded1 = buffer.readu8(DECODE_TET, Char1)
            local Key = (Char0 + Char1 * 256) * 2
            if Decoded0 < 64 and Decoded1 < 64 then
                local Byte0 = bit32.bor(bit32.lshift(Decoded0, 2), bit32.rshift(Decoded1, 4))
                local Byte1_high = bit32.band(Decoded1, 15)
                buffer.writeu16(DECODE_PAIR_A, Key, bit32.bor(Byte0, bit32.lshift(Byte1_high, 12)))

                local Byte1_low = bit32.rshift(Decoded0, 2)
                local Byte2 = bit32.bor(bit32.lshift(bit32.band(Decoded0, 3), 6), Decoded1)
                buffer.writeu16(DECODE_PAIR_B, Key, bit32.bor(Byte1_low, bit32.lshift(Byte2, 8)))
            elseif Decoded0 == 254 or Decoded1 == 254 then
                buffer.writeu16(DECODE_PAIR_A, Key, 254)
                buffer.writeu16(DECODE_PAIR_B, Key, 254)
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
    local Table = ENCODE_SEXTET_PAIR
    local Alphabet = ALPHABET_BYTES
    local TableShifted = ENCODE_SEXTET_PAIR_SHIFTED
    local InputIndex = 0
    local OutputIndex = 0
    local Chunk = 0
    local FullTripletEnd = InputLength - (InputLength % 3)

    local UnrollStop16 = InputLength - 49
    while InputIndex <= UnrollStop16 do
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
    end

    local UnrollStop4 = InputLength - 13
    while InputIndex <= UnrollStop4 do
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
        Chunk = bit32.rshift(bit32.byteswap(buffer.readu32(Input, InputIndex)), 8)
        InputIndex += 3
        buffer.writeu32(Output, OutputIndex, bit32.bor(
            buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)),
            buffer.readu32(TableShifted, bit32.lshift(bit32.band(Chunk, 4095), 2))))
        OutputIndex += 4
    end

    while InputIndex < FullTripletEnd do
        Chunk = bit32.bor(
            bit32.lshift(buffer.readu8(Input, InputIndex), 16),
            bit32.lshift(buffer.readu8(Input, InputIndex + 1), 8),
            buffer.readu8(Input, InputIndex + 2))
        buffer.writeu16(Output, OutputIndex, buffer.readu16(Table, bit32.lshift(bit32.rshift(Chunk, 12), 1)))
        buffer.writeu16(Output, OutputIndex + 2, buffer.readu16(Table, bit32.lshift(bit32.band(Chunk, 4095), 1)))
        InputIndex += 3
        OutputIndex += 4
    end

    local Remainder = InputLength - InputIndex
    if Remainder == 1 then
        local Byte0 = buffer.readu8(Input, InputIndex)
        buffer.writeu8(Output, OutputIndex, buffer.readu8(Alphabet, bit32.rshift(Byte0, 2)))
        buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(Alphabet, bit32.lshift(bit32.band(Byte0, 3), 4)))
        buffer.writeu8(Output, OutputIndex + 2, PADDING_CHARACTER)
        buffer.writeu8(Output, OutputIndex + 3, PADDING_CHARACTER)
    elseif Remainder == 2 then
        local Pair = bit32.bor(
            bit32.lshift(buffer.readu8(Input, InputIndex), 8),
            buffer.readu8(Input, InputIndex + 1))
        buffer.writeu8(Output, OutputIndex, buffer.readu8(Alphabet, bit32.rshift(Pair, 10)))
        buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(Alphabet, bit32.band(bit32.rshift(Pair, 4), 63)))
        buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(Alphabet, bit32.band(bit32.lshift(Pair, 2), 63)))
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

    local DecodePairA = DECODE_PAIR_A
    local DecodePairB = DECODE_PAIR_B
    local Dtet = DECODE_TET

    local UnrollStop16 = BodyEnd - 64
    while InputIndex <= UnrollStop16 do
        local W = buffer.readu32(Input, InputIndex)
        buffer.writeu32(Output, OutputIndex, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 4)
        buffer.writeu32(Output, OutputIndex + 3, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 8)
        buffer.writeu32(Output, OutputIndex + 6, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 12)
        buffer.writeu32(Output, OutputIndex + 9, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 16)
        buffer.writeu32(Output, OutputIndex + 12, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 20)
        buffer.writeu32(Output, OutputIndex + 15, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 24)
        buffer.writeu32(Output, OutputIndex + 18, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 28)
        buffer.writeu32(Output, OutputIndex + 21, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 32)
        buffer.writeu32(Output, OutputIndex + 24, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 36)
        buffer.writeu32(Output, OutputIndex + 27, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 40)
        buffer.writeu32(Output, OutputIndex + 30, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 44)
        buffer.writeu32(Output, OutputIndex + 33, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 48)
        buffer.writeu32(Output, OutputIndex + 36, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 52)
        buffer.writeu32(Output, OutputIndex + 39, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 56)
        buffer.writeu32(Output, OutputIndex + 42, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 60)
        buffer.writeu32(Output, OutputIndex + 45, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        InputIndex += 64
        OutputIndex += 48
    end

    local UnrollStop4 = BodyEnd - 16
    while InputIndex <= UnrollStop4 do
        local W = buffer.readu32(Input, InputIndex)
        buffer.writeu32(Output, OutputIndex, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 4)
        buffer.writeu32(Output, OutputIndex + 3, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 8)
        buffer.writeu32(Output, OutputIndex + 6, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        W = buffer.readu32(Input, InputIndex + 12)
        buffer.writeu32(Output, OutputIndex + 9, bit32.bor(buffer.readu16(DecodePairA, bit32.lshift(bit32.band(W, 0xFFFF), 1)), bit32.lshift(buffer.readu16(DecodePairB, bit32.band(bit32.rshift(W, 15), 0x1FFFE)), 8)))

        InputIndex += 16
        OutputIndex += 12
    end

    while InputIndex <= BodyEnd - 4 do
        local Word = buffer.readu32(Input, InputIndex)
        local PairA = buffer.readu16(DecodePairA, bit32.lshift(bit32.band(Word, 0xFFFF), 1))
        local PairB = buffer.readu16(DecodePairB, bit32.lshift(bit32.rshift(Word, 16), 1))
        buffer.writeu32(Output, OutputIndex, bit32.bor(PairA, bit32.lshift(PairB, 8)))
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
