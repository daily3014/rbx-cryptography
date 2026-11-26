--[=[
	ML-KEM Number Theoretic Transform Module

	Fast NTT and inverse NTT transforms for polynomial multiplication in Z_q[X]/(X^256 + 1)
	where q = 3329, plus fused base-case multiplication for dot products and matrix-vector products.
--]=]

--!strict
--!optimize 2
--!native

local Q = 3329
local INV_N = 3303
local INV_Q = 1 / Q
local IZ01_SCALED = -1652

local NZ01 = -1600
local NZ02 = -749
local NZ03 = -40
local NZ04 = -687
local NZ05 = 630
local NZ06 = -1432
local NZ07 = 848
local NZ08 = 1062
local NZ09 = -1410
local NZ10 = 193
local NZ11 = 797
local NZ12 = -543
local NZ13 = -69
local NZ14 = 569
local NZ15 = -1583
local IZ02 = 749
local IZ03 = 40
local IZ04 = 687
local IZ05 = -630
local IZ06 = 1432
local IZ07 = -848
local IZ08 = -1062
local IZ09 = 1410
local IZ10 = -193
local IZ11 = -797
local IZ12 = 543
local IZ13 = 69
local IZ14 = -569
local IZ15 = 1583

local NTT_ZETA_EXP: buffer = buffer.fromstring("\001\000\192\249\019\253\216\255\081\253\118\002\104\250\080\003\z
	\038\004\126\250\193\000\029\003\225\253\187\255\057\002\209\249\z
	\040\001\142\252\059\005\196\005\229\254\056\000\191\251\053\005\z
	\146\005\045\251\023\002\065\254\088\252\062\254\181\250\053\003\z
	\033\001\075\001\180\255\219\249\173\004\255\251\228\251\006\251\z
	\138\002\184\250\208\252\120\002\048\254\033\000\040\005\122\250\z
	\014\252\155\005\039\003\196\001\158\005\051\254\254\005\097\252\z
	\086\253\056\253\201\005\136\002\169\252\037\255\203\004\142\003\z
	\017\000\200\253\071\002\088\253\101\006\211\002\239\251\076\004\z
	\129\005\101\253\208\255\233\000\244\002\107\251\198\254\233\254\z
	\166\249\115\006\228\253\252\249\054\250\184\003\181\005\126\253\z
	\171\003\003\252\132\252\083\252\221\002\032\252\012\001\129\002\z
	\048\006\249\251\244\250\147\255\119\001\244\252\041\251\109\006\z
	\039\004\063\001\212\253\245\002\050\251\049\002\161\252\033\253\z
	\243\253\068\004\147\001\002\004\119\004\101\251\214\253\118\003\z
	\185\249\188\004\081\250\005\004\061\251\118\254\117\003\105\251")
local INTT_ZETA_EXP: buffer = buffer.fromstring("\255\255\064\006\237\002\040\000\175\002\138\253\152\005\176\252\z
	\218\251\130\005\063\255\227\252\031\002\069\000\199\253\047\006\z
	\216\254\114\003\197\250\060\250\027\001\200\255\065\004\203\250\z
	\110\250\211\004\233\253\191\001\168\003\194\001\075\005\203\252\z
	\223\254\181\254\076\000\037\006\083\251\001\004\028\004\250\004\z
	\118\253\072\005\048\003\136\253\208\001\223\255\216\250\134\005\z
	\242\003\101\250\217\252\060\254\098\250\205\001\002\250\159\003\z
	\170\002\200\002\055\250\120\253\087\003\219\000\053\251\114\252\z
	\239\255\056\002\185\253\168\002\155\249\045\253\017\004\180\251\z
	\127\250\155\002\048\000\023\255\012\253\149\004\058\001\023\001\z
	\090\006\141\249\028\002\004\006\202\005\072\252\075\250\130\002\z
	\085\252\253\003\124\003\173\003\035\253\224\003\244\254\127\253\z
	\208\249\007\004\012\005\109\000\137\254\012\003\215\004\147\249\z
	\217\251\193\254\044\002\011\253\206\004\207\253\095\003\223\002\z
	\013\002\188\251\109\254\254\251\137\251\155\004\042\002\138\252\z
	\071\006\068\251\175\005\251\251\195\004\138\001\139\252\151\004")
local POLY_MUL_ZETA_EXP: buffer = buffer.fromstring("\017\000\240\012\201\010\056\002\071\002\186\010\089\010\168\002\z
	\101\006\156\006\211\002\046\010\240\008\017\004\076\004\181\008\z
	\129\005\128\007\102\010\155\002\209\012\048\000\233\000\024\012\z
	\244\002\013\010\108\008\149\004\199\011\058\001\234\011\023\001\z
	\167\006\090\006\115\006\142\006\229\010\028\002\253\006\004\006\z
	\055\007\202\005\184\003\073\009\181\005\076\007\127\010\130\002\z
	\171\003\086\009\004\009\253\003\133\009\124\003\084\009\173\003\z
	\221\002\036\010\033\009\224\003\012\001\245\011\129\002\128\010\z
	\048\006\209\006\250\008\007\004\245\007\012\005\148\012\109\000\z
	\119\001\138\011\245\009\012\003\042\008\215\004\109\006\148\006\z
	\039\004\218\008\063\001\194\011\213\010\044\002\245\002\012\010\z
	\051\008\206\004\049\002\208\010\162\009\095\003\034\010\223\002\z
	\244\010\013\002\068\004\189\008\147\001\110\011\002\004\255\008\z
	\119\004\138\008\102\008\155\004\215\010\042\002\118\003\139\009\z
	\186\006\071\006\188\004\069\008\082\007\175\005\005\004\252\008\z
	\062\008\195\004\119\011\138\001\117\003\140\009\106\008\151\004")

local function ModQ(Value: number): number
	return Value - math.floor(Value * INV_Q + 1.5e-4) * Q
end

local function DotMul2(F: buffer, FOffset: number, G: buffer, GOffset: number, H: buffer, HOffset: number)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, 127 do
		local Offset = I * 4
		local Zeta = buffer.readu16(PolyZeta, I * 2)
		local GPair0 = buffer.readu32(G, GOffset + Offset)
		local G00 = bit32.band(GPair0, 0xFFFF)
		local G10 = bit32.rshift(GPair0, 16)
		local G1Zeta0 = G10 * Zeta
		local GPair1 = buffer.readu32(G, GOffset + Offset + 512)
		local G01 = bit32.band(GPair1, 0xFFFF)
		local G11 = bit32.rshift(GPair1, 16)
		local G1Zeta1 = G11 * Zeta
		local Out = HOffset + Offset
		local Acc0, Acc1 = 0, 0
		local FPairF0_ = buffer.readu32(F, FOffset + Offset); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
		Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
		Acc1 = F0_0 * G10 + F0_1 * G00
		local FPairF1_ = buffer.readu32(F, FOffset + Offset + 512); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
		Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
		Acc1 += F1_0 * G11 + F1_1 * G01
		buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
		buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
	end
end
local function DotMul3(F: buffer, FOffset: number, G: buffer, GOffset: number, H: buffer, HOffset: number)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, 127 do
		local Offset = I * 4
		local Zeta = buffer.readu16(PolyZeta, I * 2)
		local GPair0 = buffer.readu32(G, GOffset + Offset)
		local G00 = bit32.band(GPair0, 0xFFFF)
		local G10 = bit32.rshift(GPair0, 16)
		local G1Zeta0 = G10 * Zeta
		local GPair1 = buffer.readu32(G, GOffset + Offset + 512)
		local G01 = bit32.band(GPair1, 0xFFFF)
		local G11 = bit32.rshift(GPair1, 16)
		local G1Zeta1 = G11 * Zeta
		local GPair2 = buffer.readu32(G, GOffset + Offset + 1024)
		local G02 = bit32.band(GPair2, 0xFFFF)
		local G12 = bit32.rshift(GPair2, 16)
		local G1Zeta2 = G12 * Zeta
		local Out = HOffset + Offset
		local Acc0, Acc1 = 0, 0
		local FPairF0_ = buffer.readu32(F, FOffset + Offset); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
		Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
		Acc1 = F0_0 * G10 + F0_1 * G00
		local FPairF1_ = buffer.readu32(F, FOffset + Offset + 512); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
		Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
		Acc1 += F1_0 * G11 + F1_1 * G01
		local FPairF2_ = buffer.readu32(F, FOffset + Offset + 1024); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
		Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
		Acc1 += F2_0 * G12 + F2_1 * G02
		buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
		buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
	end
end
local function DotMul4(F: buffer, FOffset: number, G: buffer, GOffset: number, H: buffer, HOffset: number)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, 127 do
		local Offset = I * 4
		local Zeta = buffer.readu16(PolyZeta, I * 2)
		local GPair0 = buffer.readu32(G, GOffset + Offset)
		local G00 = bit32.band(GPair0, 0xFFFF)
		local G10 = bit32.rshift(GPair0, 16)
		local G1Zeta0 = G10 * Zeta
		local GPair1 = buffer.readu32(G, GOffset + Offset + 512)
		local G01 = bit32.band(GPair1, 0xFFFF)
		local G11 = bit32.rshift(GPair1, 16)
		local G1Zeta1 = G11 * Zeta
		local GPair2 = buffer.readu32(G, GOffset + Offset + 1024)
		local G02 = bit32.band(GPair2, 0xFFFF)
		local G12 = bit32.rshift(GPair2, 16)
		local G1Zeta2 = G12 * Zeta
		local GPair3 = buffer.readu32(G, GOffset + Offset + 1536)
		local G03 = bit32.band(GPair3, 0xFFFF)
		local G13 = bit32.rshift(GPair3, 16)
		local G1Zeta3 = G13 * Zeta
		local Out = HOffset + Offset
		local Acc0, Acc1 = 0, 0
		local FPairF0_ = buffer.readu32(F, FOffset + Offset); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
		Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
		Acc1 = F0_0 * G10 + F0_1 * G00
		local FPairF1_ = buffer.readu32(F, FOffset + Offset + 512); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
		Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
		Acc1 += F1_0 * G11 + F1_1 * G01
		local FPairF2_ = buffer.readu32(F, FOffset + Offset + 1024); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
		Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
		Acc1 += F2_0 * G12 + F2_1 * G02
		local FPairF3_ = buffer.readu32(F, FOffset + Offset + 1536); local F3_0, F3_1 = bit32.band(FPairF3_, 0xFFFF), bit32.rshift(FPairF3_, 16)
		Acc0 += F3_0 * G03 + F3_1 * G1Zeta3
		Acc1 += F3_0 * G13 + F3_1 * G03
		buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
		buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
	end
end
local function MatrixAccumulate2(F: buffer, G: buffer, H: buffer)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, 127 do
		local Offset = I * 4
		local Zeta = buffer.readu16(PolyZeta, I * 2)
		local GPair0 = buffer.readu32(G, Offset)
		local G00 = bit32.band(GPair0, 0xFFFF)
		local G10 = bit32.rshift(GPair0, 16)
		local G1Zeta0 = G10 * Zeta
		local GPair1 = buffer.readu32(G, Offset + 512)
		local G01 = bit32.band(GPair1, 0xFFFF)
		local G11 = bit32.rshift(GPair1, 16)
		local G1Zeta1 = G11 * Zeta
		do
			local Out = Offset
			local Acc0 = buffer.readu16(H, Out)
			local Acc1 = buffer.readu16(H, Out + 2)
			local FPairF0_ = buffer.readu32(F, Offset); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 += F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 += F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 512); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 512
			local Acc0 = buffer.readu16(H, Out)
			local Acc1 = buffer.readu16(H, Out + 2)
			local FPairF0_ = buffer.readu32(F, Offset + 1024); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 += F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 += F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 1536); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
	end
end
local function MatrixAccumulate3(F: buffer, G: buffer, H: buffer)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, 127 do
		local Offset = I * 4
		local Zeta = buffer.readu16(PolyZeta, I * 2)
		local GPair0 = buffer.readu32(G, Offset)
		local G00 = bit32.band(GPair0, 0xFFFF)
		local G10 = bit32.rshift(GPair0, 16)
		local G1Zeta0 = G10 * Zeta
		local GPair1 = buffer.readu32(G, Offset + 512)
		local G01 = bit32.band(GPair1, 0xFFFF)
		local G11 = bit32.rshift(GPair1, 16)
		local G1Zeta1 = G11 * Zeta
		local GPair2 = buffer.readu32(G, Offset + 1024)
		local G02 = bit32.band(GPair2, 0xFFFF)
		local G12 = bit32.rshift(GPair2, 16)
		local G1Zeta2 = G12 * Zeta
		do
			local Out = Offset
			local Acc0 = buffer.readu16(H, Out)
			local Acc1 = buffer.readu16(H, Out + 2)
			local FPairF0_ = buffer.readu32(F, Offset); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 += F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 += F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 512); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 1024); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 512
			local Acc0 = buffer.readu16(H, Out)
			local Acc1 = buffer.readu16(H, Out + 2)
			local FPairF0_ = buffer.readu32(F, Offset + 1536); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 += F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 += F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 2048); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 2560); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 1024
			local Acc0 = buffer.readu16(H, Out)
			local Acc1 = buffer.readu16(H, Out + 2)
			local FPairF0_ = buffer.readu32(F, Offset + 3072); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 += F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 += F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 3584); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 4096); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
	end
end
local function MatrixAccumulate4(F: buffer, G: buffer, H: buffer)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, 127 do
		local Offset = I * 4
		local Zeta = buffer.readu16(PolyZeta, I * 2)
		local GPair0 = buffer.readu32(G, Offset)
		local G00 = bit32.band(GPair0, 0xFFFF)
		local G10 = bit32.rshift(GPair0, 16)
		local G1Zeta0 = G10 * Zeta
		local GPair1 = buffer.readu32(G, Offset + 512)
		local G01 = bit32.band(GPair1, 0xFFFF)
		local G11 = bit32.rshift(GPair1, 16)
		local G1Zeta1 = G11 * Zeta
		local GPair2 = buffer.readu32(G, Offset + 1024)
		local G02 = bit32.band(GPair2, 0xFFFF)
		local G12 = bit32.rshift(GPair2, 16)
		local G1Zeta2 = G12 * Zeta
		local GPair3 = buffer.readu32(G, Offset + 1536)
		local G03 = bit32.band(GPair3, 0xFFFF)
		local G13 = bit32.rshift(GPair3, 16)
		local G1Zeta3 = G13 * Zeta
		do
			local Out = Offset
			local Acc0 = buffer.readu16(H, Out)
			local Acc1 = buffer.readu16(H, Out + 2)
			local FPairF0_ = buffer.readu32(F, Offset); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 += F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 += F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 512); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 1024); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			local FPairF3_ = buffer.readu32(F, Offset + 1536); local F3_0, F3_1 = bit32.band(FPairF3_, 0xFFFF), bit32.rshift(FPairF3_, 16)
			Acc0 += F3_0 * G03 + F3_1 * G1Zeta3
			Acc1 += F3_0 * G13 + F3_1 * G03
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 512
			local Acc0 = buffer.readu16(H, Out)
			local Acc1 = buffer.readu16(H, Out + 2)
			local FPairF0_ = buffer.readu32(F, Offset + 2048); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 += F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 += F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 2560); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 3072); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			local FPairF3_ = buffer.readu32(F, Offset + 3584); local F3_0, F3_1 = bit32.band(FPairF3_, 0xFFFF), bit32.rshift(FPairF3_, 16)
			Acc0 += F3_0 * G03 + F3_1 * G1Zeta3
			Acc1 += F3_0 * G13 + F3_1 * G03
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 1024
			local Acc0 = buffer.readu16(H, Out)
			local Acc1 = buffer.readu16(H, Out + 2)
			local FPairF0_ = buffer.readu32(F, Offset + 4096); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 += F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 += F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 4608); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 5120); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			local FPairF3_ = buffer.readu32(F, Offset + 5632); local F3_0, F3_1 = bit32.band(FPairF3_, 0xFFFF), bit32.rshift(FPairF3_, 16)
			Acc0 += F3_0 * G03 + F3_1 * G1Zeta3
			Acc1 += F3_0 * G13 + F3_1 * G03
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 1536
			local Acc0 = buffer.readu16(H, Out)
			local Acc1 = buffer.readu16(H, Out + 2)
			local FPairF0_ = buffer.readu32(F, Offset + 6144); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 += F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 += F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 6656); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 7168); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			local FPairF3_ = buffer.readu32(F, Offset + 7680); local F3_0, F3_1 = bit32.band(FPairF3_, 0xFFFF), bit32.rshift(FPairF3_, 16)
			Acc0 += F3_0 * G03 + F3_1 * G1Zeta3
			Acc1 += F3_0 * G13 + F3_1 * G03
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
	end
end
local function MatrixMul2(F: buffer, G: buffer, H: buffer)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, 127 do
		local Offset = I * 4
		local Zeta = buffer.readu16(PolyZeta, I * 2)
		local GPair0 = buffer.readu32(G, Offset)
		local G00 = bit32.band(GPair0, 0xFFFF)
		local G10 = bit32.rshift(GPair0, 16)
		local G1Zeta0 = G10 * Zeta
		local GPair1 = buffer.readu32(G, Offset + 512)
		local G01 = bit32.band(GPair1, 0xFFFF)
		local G11 = bit32.rshift(GPair1, 16)
		local G1Zeta1 = G11 * Zeta
		do
			local Out = Offset
			local Acc0, Acc1 = 0, 0
			local FPairF0_ = buffer.readu32(F, Offset); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 = F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 512); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 512
			local Acc0, Acc1 = 0, 0
			local FPairF0_ = buffer.readu32(F, Offset + 1024); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 = F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 1536); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
	end
end
local function MatrixMul3(F: buffer, G: buffer, H: buffer)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, 127 do
		local Offset = I * 4
		local Zeta = buffer.readu16(PolyZeta, I * 2)
		local GPair0 = buffer.readu32(G, Offset)
		local G00 = bit32.band(GPair0, 0xFFFF)
		local G10 = bit32.rshift(GPair0, 16)
		local G1Zeta0 = G10 * Zeta
		local GPair1 = buffer.readu32(G, Offset + 512)
		local G01 = bit32.band(GPair1, 0xFFFF)
		local G11 = bit32.rshift(GPair1, 16)
		local G1Zeta1 = G11 * Zeta
		local GPair2 = buffer.readu32(G, Offset + 1024)
		local G02 = bit32.band(GPair2, 0xFFFF)
		local G12 = bit32.rshift(GPair2, 16)
		local G1Zeta2 = G12 * Zeta
		do
			local Out = Offset
			local Acc0, Acc1 = 0, 0
			local FPairF0_ = buffer.readu32(F, Offset); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 = F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 512); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 1024); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 512
			local Acc0, Acc1 = 0, 0
			local FPairF0_ = buffer.readu32(F, Offset + 1536); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 = F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 2048); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 2560); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 1024
			local Acc0, Acc1 = 0, 0
			local FPairF0_ = buffer.readu32(F, Offset + 3072); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 = F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 3584); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 4096); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
	end
end
local function MatrixMul4(F: buffer, G: buffer, H: buffer)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, 127 do
		local Offset = I * 4
		local Zeta = buffer.readu16(PolyZeta, I * 2)
		local GPair0 = buffer.readu32(G, Offset)
		local G00 = bit32.band(GPair0, 0xFFFF)
		local G10 = bit32.rshift(GPair0, 16)
		local G1Zeta0 = G10 * Zeta
		local GPair1 = buffer.readu32(G, Offset + 512)
		local G01 = bit32.band(GPair1, 0xFFFF)
		local G11 = bit32.rshift(GPair1, 16)
		local G1Zeta1 = G11 * Zeta
		local GPair2 = buffer.readu32(G, Offset + 1024)
		local G02 = bit32.band(GPair2, 0xFFFF)
		local G12 = bit32.rshift(GPair2, 16)
		local G1Zeta2 = G12 * Zeta
		local GPair3 = buffer.readu32(G, Offset + 1536)
		local G03 = bit32.band(GPair3, 0xFFFF)
		local G13 = bit32.rshift(GPair3, 16)
		local G1Zeta3 = G13 * Zeta
		do
			local Out = Offset
			local Acc0, Acc1 = 0, 0
			local FPairF0_ = buffer.readu32(F, Offset); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 = F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 512); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 1024); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			local FPairF3_ = buffer.readu32(F, Offset + 1536); local F3_0, F3_1 = bit32.band(FPairF3_, 0xFFFF), bit32.rshift(FPairF3_, 16)
			Acc0 += F3_0 * G03 + F3_1 * G1Zeta3
			Acc1 += F3_0 * G13 + F3_1 * G03
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 512
			local Acc0, Acc1 = 0, 0
			local FPairF0_ = buffer.readu32(F, Offset + 2048); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 = F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 2560); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 3072); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			local FPairF3_ = buffer.readu32(F, Offset + 3584); local F3_0, F3_1 = bit32.band(FPairF3_, 0xFFFF), bit32.rshift(FPairF3_, 16)
			Acc0 += F3_0 * G03 + F3_1 * G1Zeta3
			Acc1 += F3_0 * G13 + F3_1 * G03
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 1024
			local Acc0, Acc1 = 0, 0
			local FPairF0_ = buffer.readu32(F, Offset + 4096); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 = F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 4608); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 5120); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			local FPairF3_ = buffer.readu32(F, Offset + 5632); local F3_0, F3_1 = bit32.band(FPairF3_, 0xFFFF), bit32.rshift(FPairF3_, 16)
			Acc0 += F3_0 * G03 + F3_1 * G1Zeta3
			Acc1 += F3_0 * G13 + F3_1 * G03
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
		do
			local Out = Offset + 1536
			local Acc0, Acc1 = 0, 0
			local FPairF0_ = buffer.readu32(F, Offset + 6144); local F0_0, F0_1 = bit32.band(FPairF0_, 0xFFFF), bit32.rshift(FPairF0_, 16)
			Acc0 = F0_0 * G00 + F0_1 * G1Zeta0
			Acc1 = F0_0 * G10 + F0_1 * G00
			local FPairF1_ = buffer.readu32(F, Offset + 6656); local F1_0, F1_1 = bit32.band(FPairF1_, 0xFFFF), bit32.rshift(FPairF1_, 16)
			Acc0 += F1_0 * G01 + F1_1 * G1Zeta1
			Acc1 += F1_0 * G11 + F1_1 * G01
			local FPairF2_ = buffer.readu32(F, Offset + 7168); local F2_0, F2_1 = bit32.band(FPairF2_, 0xFFFF), bit32.rshift(FPairF2_, 16)
			Acc0 += F2_0 * G02 + F2_1 * G1Zeta2
			Acc1 += F2_0 * G12 + F2_1 * G02
			local FPairF3_ = buffer.readu32(F, Offset + 7680); local F3_0, F3_1 = bit32.band(FPairF3_, 0xFFFF), bit32.rshift(FPairF3_, 16)
			Acc0 += F3_0 * G03 + F3_1 * G1Zeta3
			Acc1 += F3_0 * G13 + F3_1 * G03
			buffer.writeu16(H, Out, Acc0 - math.floor(Acc0 * INV_Q + 1.5e-4) * Q)
			buffer.writeu16(H, Out + 2, Acc1 - math.floor(Acc1 * INV_Q + 1.5e-4) * Q)
		end
	end
end

local Ntt = {}

function Ntt.NttAt(Poly: buffer, BaseOffset: number): ()
	local Zeta = NTT_ZETA_EXP
	for Group = 0, 30, 2 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu16(Poly, Base + 0)
		local C01 = buffer.readu16(Poly, Base + 32)
		local C02 = buffer.readu16(Poly, Base + 64)
		local C03 = buffer.readu16(Poly, Base + 96)
		local C04 = buffer.readu16(Poly, Base + 128)
		local C05 = buffer.readu16(Poly, Base + 160)
		local C06 = buffer.readu16(Poly, Base + 192)
		local C07 = buffer.readu16(Poly, Base + 224)
		local C08 = buffer.readu16(Poly, Base + 256)
		local C09 = buffer.readu16(Poly, Base + 288)
		local C10 = buffer.readu16(Poly, Base + 320)
		local C11 = buffer.readu16(Poly, Base + 352)
		local C12 = buffer.readu16(Poly, Base + 384)
		local C13 = buffer.readu16(Poly, Base + 416)
		local C14 = buffer.readu16(Poly, Base + 448)
		local C15 = buffer.readu16(Poly, Base + 480)
		do local T = C08 * NZ01; C08 = C00 - T; C00 += T end
		do local T = C09 * NZ01; C09 = C01 - T; C01 += T end
		do local T = C10 * NZ01; C10 = C02 - T; C02 += T end
		do local T = C11 * NZ01; C11 = C03 - T; C03 += T end
		do local T = C12 * NZ01; C12 = C04 - T; C04 += T end
		do local T = C13 * NZ01; C13 = C05 - T; C05 += T end
		do local T = C14 * NZ01; C14 = C06 - T; C06 += T end
		do local T = C15 * NZ01; C15 = C07 - T; C07 += T end
		do local T = C04 * NZ02; C04 = C00 - T; C00 += T end
		do local T = C05 * NZ02; C05 = C01 - T; C01 += T end
		do local T = C06 * NZ02; C06 = C02 - T; C02 += T end
		do local T = C07 * NZ02; C07 = C03 - T; C03 += T end
		do local T = C12 * NZ03; C12 = C08 - T; C08 += T end
		do local T = C13 * NZ03; C13 = C09 - T; C09 += T end
		do local T = C14 * NZ03; C14 = C10 - T; C10 += T end
		do local T = C15 * NZ03; C15 = C11 - T; C11 += T end
		C00 = ModQ(C00)
		C01 = ModQ(C01)
		C02 = ModQ(C02)
		C03 = ModQ(C03)
		C04 = ModQ(C04)
		C05 = ModQ(C05)
		C06 = ModQ(C06)
		C07 = ModQ(C07)
		C08 = ModQ(C08)
		C09 = ModQ(C09)
		C10 = ModQ(C10)
		C11 = ModQ(C11)
		C12 = ModQ(C12)
		C13 = ModQ(C13)
		C14 = ModQ(C14)
		C15 = ModQ(C15)
		do local T = C02 * NZ04; C02 = C00 - T; C00 += T end
		do local T = C03 * NZ04; C03 = C01 - T; C01 += T end
		do local T = C06 * NZ05; C06 = C04 - T; C04 += T end
		do local T = C07 * NZ05; C07 = C05 - T; C05 += T end
		do local T = C10 * NZ06; C10 = C08 - T; C08 += T end
		do local T = C11 * NZ06; C11 = C09 - T; C09 += T end
		do local T = C14 * NZ07; C14 = C12 - T; C12 += T end
		do local T = C15 * NZ07; C15 = C13 - T; C13 += T end
		do local T = C01 * NZ08; C01 = C00 - T; C00 += T end
		do local T = C03 * NZ09; C03 = C02 - T; C02 += T end
		do local T = C05 * NZ10; C05 = C04 - T; C04 += T end
		do local T = C07 * NZ11; C07 = C06 - T; C06 += T end
		do local T = C09 * NZ12; C09 = C08 - T; C08 += T end
		do local T = C11 * NZ13; C11 = C10 - T; C10 += T end
		do local T = C13 * NZ14; C13 = C12 - T; C12 += T end
		do local T = C15 * NZ15; C15 = C14 - T; C14 += T end
		buffer.writeu16(Poly, Base + 0, ModQ(C00))
		buffer.writeu16(Poly, Base + 32, ModQ(C01))
		buffer.writeu16(Poly, Base + 64, ModQ(C02))
		buffer.writeu16(Poly, Base + 96, ModQ(C03))
		buffer.writeu16(Poly, Base + 128, ModQ(C04))
		buffer.writeu16(Poly, Base + 160, ModQ(C05))
		buffer.writeu16(Poly, Base + 192, ModQ(C06))
		buffer.writeu16(Poly, Base + 224, ModQ(C07))
		buffer.writeu16(Poly, Base + 256, ModQ(C08))
		buffer.writeu16(Poly, Base + 288, ModQ(C09))
		buffer.writeu16(Poly, Base + 320, ModQ(C10))
		buffer.writeu16(Poly, Base + 352, ModQ(C11))
		buffer.writeu16(Poly, Base + 384, ModQ(C12))
		buffer.writeu16(Poly, Base + 416, ModQ(C13))
		buffer.writeu16(Poly, Base + 448, ModQ(C14))
		buffer.writeu16(Poly, Base + 480, ModQ(C15))
	end
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 32
		local Y0 = buffer.readi16(Zeta, 32 + Block * 2)
		local Y1 = buffer.readi16(Zeta, 64 + Block * 4)
		local Y2 = buffer.readi16(Zeta, 66 + Block * 4)
		local X0 = buffer.readi16(Zeta, 128 + Block * 8)
		local X1 = buffer.readi16(Zeta, 130 + Block * 8)
		local X2 = buffer.readi16(Zeta, 132 + Block * 8)
		local X3 = buffer.readi16(Zeta, 134 + Block * 8)
		local C00 = buffer.readu16(Poly, Base + 0)
		local C01 = buffer.readu16(Poly, Base + 2)
		local C02 = buffer.readu16(Poly, Base + 4)
		local C03 = buffer.readu16(Poly, Base + 6)
		local C04 = buffer.readu16(Poly, Base + 8)
		local C05 = buffer.readu16(Poly, Base + 10)
		local C06 = buffer.readu16(Poly, Base + 12)
		local C07 = buffer.readu16(Poly, Base + 14)
		local C08 = buffer.readu16(Poly, Base + 16)
		local C09 = buffer.readu16(Poly, Base + 18)
		local C10 = buffer.readu16(Poly, Base + 20)
		local C11 = buffer.readu16(Poly, Base + 22)
		local C12 = buffer.readu16(Poly, Base + 24)
		local C13 = buffer.readu16(Poly, Base + 26)
		local C14 = buffer.readu16(Poly, Base + 28)
		local C15 = buffer.readu16(Poly, Base + 30)
		do local T = Y0 * C08; C08 = C00 - T; C00 += T end
		do local T = Y0 * C09; C09 = C01 - T; C01 += T end
		do local T = Y0 * C10; C10 = C02 - T; C02 += T end
		do local T = Y0 * C11; C11 = C03 - T; C03 += T end
		do local T = Y0 * C12; C12 = C04 - T; C04 += T end
		do local T = Y0 * C13; C13 = C05 - T; C05 += T end
		do local T = Y0 * C14; C14 = C06 - T; C06 += T end
		do local T = Y0 * C15; C15 = C07 - T; C07 += T end
		do local T = Y1 * C04; C04 = C00 - T; C00 += T end
		do local T = Y1 * C05; C05 = C01 - T; C01 += T end
		do local T = Y1 * C06; C06 = C02 - T; C02 += T end
		do local T = Y1 * C07; C07 = C03 - T; C03 += T end
		do local T = Y2 * C12; C12 = C08 - T; C08 += T end
		do local T = Y2 * C13; C13 = C09 - T; C09 += T end
		do local T = Y2 * C14; C14 = C10 - T; C10 += T end
		do local T = Y2 * C15; C15 = C11 - T; C11 += T end
		do local T = X0 * C02; C02 = C00 - T; C00 += T end
		do local T = X0 * C03; C03 = C01 - T; C01 += T end
		do local T = X1 * C06; C06 = C04 - T; C04 += T end
		do local T = X1 * C07; C07 = C05 - T; C05 += T end
		do local T = X2 * C10; C10 = C08 - T; C08 += T end
		do local T = X2 * C11; C11 = C09 - T; C09 += T end
		do local T = X3 * C14; C14 = C12 - T; C12 += T end
		do local T = X3 * C15; C15 = C13 - T; C13 += T end
		buffer.writeu16(Poly, Base + 0, ModQ(C00))
		buffer.writeu16(Poly, Base + 2, ModQ(C01))
		buffer.writeu16(Poly, Base + 4, ModQ(C02))
		buffer.writeu16(Poly, Base + 6, ModQ(C03))
		buffer.writeu16(Poly, Base + 8, ModQ(C04))
		buffer.writeu16(Poly, Base + 10, ModQ(C05))
		buffer.writeu16(Poly, Base + 12, ModQ(C06))
		buffer.writeu16(Poly, Base + 14, ModQ(C07))
		buffer.writeu16(Poly, Base + 16, ModQ(C08))
		buffer.writeu16(Poly, Base + 18, ModQ(C09))
		buffer.writeu16(Poly, Base + 20, ModQ(C10))
		buffer.writeu16(Poly, Base + 22, ModQ(C11))
		buffer.writeu16(Poly, Base + 24, ModQ(C12))
		buffer.writeu16(Poly, Base + 26, ModQ(C13))
		buffer.writeu16(Poly, Base + 28, ModQ(C14))
		buffer.writeu16(Poly, Base + 30, ModQ(C15))
	end
end

function Ntt.InttAt(Poly: buffer, BaseOffset: number): ()
	local Zeta = INTT_ZETA_EXP
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 32
		local X0 = buffer.readi16(Zeta, 254 - Block * 8)
		local X1 = buffer.readi16(Zeta, 252 - Block * 8)
		local X2 = buffer.readi16(Zeta, 250 - Block * 8)
		local X3 = buffer.readi16(Zeta, 248 - Block * 8)
		local Y1 = buffer.readi16(Zeta, 126 - Block * 4)
		local Y2 = buffer.readi16(Zeta, 124 - Block * 4)
		local Y0 = buffer.readi16(Zeta, 62 - Block * 2)
		local C00 = buffer.readu16(Poly, Base + 0)
		local C01 = buffer.readu16(Poly, Base + 2)
		local C02 = buffer.readu16(Poly, Base + 4)
		local C03 = buffer.readu16(Poly, Base + 6)
		local C04 = buffer.readu16(Poly, Base + 8)
		local C05 = buffer.readu16(Poly, Base + 10)
		local C06 = buffer.readu16(Poly, Base + 12)
		local C07 = buffer.readu16(Poly, Base + 14)
		local C08 = buffer.readu16(Poly, Base + 16)
		local C09 = buffer.readu16(Poly, Base + 18)
		local C10 = buffer.readu16(Poly, Base + 20)
		local C11 = buffer.readu16(Poly, Base + 22)
		local C12 = buffer.readu16(Poly, Base + 24)
		local C13 = buffer.readu16(Poly, Base + 26)
		local C14 = buffer.readu16(Poly, Base + 28)
		local C15 = buffer.readu16(Poly, Base + 30)
		do local S = C00 + C02; C02 = (C00 - C02) * X0; C00 = S end
		do local S = C01 + C03; C03 = (C01 - C03) * X0; C01 = S end
		do local S = C04 + C06; C06 = (C04 - C06) * X1; C04 = S end
		do local S = C05 + C07; C07 = (C05 - C07) * X1; C05 = S end
		do local S = C08 + C10; C10 = (C08 - C10) * X2; C08 = S end
		do local S = C09 + C11; C11 = (C09 - C11) * X2; C09 = S end
		do local S = C12 + C14; C14 = (C12 - C14) * X3; C12 = S end
		do local S = C13 + C15; C15 = (C13 - C15) * X3; C13 = S end
		do local S = C00 + C04; C04 = (C00 - C04) * Y1; C00 = S end
		do local S = C01 + C05; C05 = (C01 - C05) * Y1; C01 = S end
		do local S = C02 + C06; C06 = (C02 - C06) * Y1; C02 = S end
		do local S = C03 + C07; C07 = (C03 - C07) * Y1; C03 = S end
		do local S = C08 + C12; C12 = (C08 - C12) * Y2; C08 = S end
		do local S = C09 + C13; C13 = (C09 - C13) * Y2; C09 = S end
		do local S = C10 + C14; C14 = (C10 - C14) * Y2; C10 = S end
		do local S = C11 + C15; C15 = (C11 - C15) * Y2; C11 = S end
		do local S = C00 + C08; C08 = (C00 - C08) * Y0; C00 = S end
		do local S = C01 + C09; C09 = (C01 - C09) * Y0; C01 = S end
		do local S = C02 + C10; C10 = (C02 - C10) * Y0; C02 = S end
		do local S = C03 + C11; C11 = (C03 - C11) * Y0; C03 = S end
		do local S = C04 + C12; C12 = (C04 - C12) * Y0; C04 = S end
		do local S = C05 + C13; C13 = (C05 - C13) * Y0; C05 = S end
		do local S = C06 + C14; C14 = (C06 - C14) * Y0; C06 = S end
		do local S = C07 + C15; C15 = (C07 - C15) * Y0; C07 = S end
		buffer.writeu16(Poly, Base + 0, C00)
		buffer.writeu16(Poly, Base + 2, C01)
		buffer.writeu16(Poly, Base + 4, ModQ(C02))
		buffer.writeu16(Poly, Base + 6, ModQ(C03))
		buffer.writeu16(Poly, Base + 8, ModQ(C04))
		buffer.writeu16(Poly, Base + 10, ModQ(C05))
		buffer.writeu16(Poly, Base + 12, ModQ(C06))
		buffer.writeu16(Poly, Base + 14, ModQ(C07))
		buffer.writeu16(Poly, Base + 16, ModQ(C08))
		buffer.writeu16(Poly, Base + 18, ModQ(C09))
		buffer.writeu16(Poly, Base + 20, ModQ(C10))
		buffer.writeu16(Poly, Base + 22, ModQ(C11))
		buffer.writeu16(Poly, Base + 24, ModQ(C12))
		buffer.writeu16(Poly, Base + 26, ModQ(C13))
		buffer.writeu16(Poly, Base + 28, ModQ(C14))
		buffer.writeu16(Poly, Base + 30, ModQ(C15))
	end
	for Group = 0, 30, 2 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu16(Poly, Base + 0)
		local C01 = buffer.readu16(Poly, Base + 32)
		local C02 = buffer.readu16(Poly, Base + 64)
		local C03 = buffer.readu16(Poly, Base + 96)
		local C04 = buffer.readu16(Poly, Base + 128)
		local C05 = buffer.readu16(Poly, Base + 160)
		local C06 = buffer.readu16(Poly, Base + 192)
		local C07 = buffer.readu16(Poly, Base + 224)
		local C08 = buffer.readu16(Poly, Base + 256)
		local C09 = buffer.readu16(Poly, Base + 288)
		local C10 = buffer.readu16(Poly, Base + 320)
		local C11 = buffer.readu16(Poly, Base + 352)
		local C12 = buffer.readu16(Poly, Base + 384)
		local C13 = buffer.readu16(Poly, Base + 416)
		local C14 = buffer.readu16(Poly, Base + 448)
		local C15 = buffer.readu16(Poly, Base + 480)
		do local S = C00 + C01; C01 = (C00 - C01) * IZ15; C00 = S end
		do local S = C02 + C03; C03 = (C02 - C03) * IZ14; C02 = S end
		do local S = C04 + C05; C05 = (C04 - C05) * IZ13; C04 = S end
		do local S = C06 + C07; C07 = (C06 - C07) * IZ12; C06 = S end
		do local S = C08 + C09; C09 = (C08 - C09) * IZ11; C08 = S end
		do local S = C10 + C11; C11 = (C10 - C11) * IZ10; C10 = S end
		do local S = C12 + C13; C13 = (C12 - C13) * IZ09; C12 = S end
		do local S = C14 + C15; C15 = (C14 - C15) * IZ08; C14 = S end
		do local S = C00 + C02; C02 = (C00 - C02) * IZ07; C00 = S end
		do local S = C01 + C03; C03 = (C01 - C03) * IZ07; C01 = S end
		do local S = C04 + C06; C06 = (C04 - C06) * IZ06; C04 = S end
		do local S = C05 + C07; C07 = (C05 - C07) * IZ06; C05 = S end
		do local S = C08 + C10; C10 = (C08 - C10) * IZ05; C08 = S end
		do local S = C09 + C11; C11 = (C09 - C11) * IZ05; C09 = S end
		do local S = C12 + C14; C14 = (C12 - C14) * IZ04; C12 = S end
		do local S = C13 + C15; C15 = (C13 - C15) * IZ04; C13 = S end
		C01 = ModQ(C01)
		C02 = ModQ(C02)
		C03 = ModQ(C03)
		C05 = ModQ(C05)
		C06 = ModQ(C06)
		C07 = ModQ(C07)
		C09 = ModQ(C09)
		C10 = ModQ(C10)
		C11 = ModQ(C11)
		C13 = ModQ(C13)
		C14 = ModQ(C14)
		C15 = ModQ(C15)
		do local S = C00 + C04; C04 = (C00 - C04) * IZ03; C00 = S end
		do local S = C01 + C05; C05 = (C01 - C05) * IZ03; C01 = S end
		do local S = C02 + C06; C06 = (C02 - C06) * IZ03; C02 = S end
		do local S = C03 + C07; C07 = (C03 - C07) * IZ03; C03 = S end
		do local S = C08 + C12; C12 = (C08 - C12) * IZ02; C08 = S end
		do local S = C09 + C13; C13 = (C09 - C13) * IZ02; C09 = S end
		do local S = C10 + C14; C14 = (C10 - C14) * IZ02; C10 = S end
		do local S = C11 + C15; C15 = (C11 - C15) * IZ02; C11 = S end
		do local S = C00 + C08; C08 = ModQ((C00 - C08) * IZ01_SCALED); C00 = ModQ(S * INV_N) end
		do local S = C01 + C09; C09 = ModQ((C01 - C09) * IZ01_SCALED); C01 = ModQ(S * INV_N) end
		do local S = C02 + C10; C10 = ModQ((C02 - C10) * IZ01_SCALED); C02 = ModQ(S * INV_N) end
		do local S = C03 + C11; C11 = ModQ((C03 - C11) * IZ01_SCALED); C03 = ModQ(S * INV_N) end
		do local S = C04 + C12; C12 = ModQ((C04 - C12) * IZ01_SCALED); C04 = ModQ(S * INV_N) end
		do local S = C05 + C13; C13 = ModQ((C05 - C13) * IZ01_SCALED); C05 = ModQ(S * INV_N) end
		do local S = C06 + C14; C14 = ModQ((C06 - C14) * IZ01_SCALED); C06 = ModQ(S * INV_N) end
		do local S = C07 + C15; C15 = ModQ((C07 - C15) * IZ01_SCALED); C07 = ModQ(S * INV_N) end
		buffer.writeu16(Poly, Base + 0, C00)
		buffer.writeu16(Poly, Base + 32, C01)
		buffer.writeu16(Poly, Base + 64, C02)
		buffer.writeu16(Poly, Base + 96, C03)
		buffer.writeu16(Poly, Base + 128, C04)
		buffer.writeu16(Poly, Base + 160, C05)
		buffer.writeu16(Poly, Base + 192, C06)
		buffer.writeu16(Poly, Base + 224, C07)
		buffer.writeu16(Poly, Base + 256, C08)
		buffer.writeu16(Poly, Base + 288, C09)
		buffer.writeu16(Poly, Base + 320, C10)
		buffer.writeu16(Poly, Base + 352, C11)
		buffer.writeu16(Poly, Base + 384, C12)
		buffer.writeu16(Poly, Base + 416, C13)
		buffer.writeu16(Poly, Base + 448, C14)
		buffer.writeu16(Poly, Base + 480, C15)
	end
end

function Ntt.DotMul(F: buffer, FOffset: number, G: buffer, GOffset: number, K: number, H: buffer, HOffset: number): ()
	if K == 2 then
		DotMul2(F, FOffset, G, GOffset, H, HOffset)
	elseif K == 3 then
		DotMul3(F, FOffset, G, GOffset, H, HOffset)
	else
		DotMul4(F, FOffset, G, GOffset, H, HOffset)
	end
end

function Ntt.MatrixAccumulate(F: buffer, G: buffer, H: buffer, K: number): ()
	if K == 2 then
		MatrixAccumulate2(F, G, H)
	elseif K == 3 then
		MatrixAccumulate3(F, G, H)
	else
		MatrixAccumulate4(F, G, H)
	end
end

function Ntt.MatrixMul(F: buffer, G: buffer, H: buffer, K: number): ()
	if K == 2 then
		MatrixMul2(F, G, H)
	elseif K == 3 then
		MatrixMul3(F, G, H)
	else
		MatrixMul4(F, G, H)
	end
end

return Ntt
