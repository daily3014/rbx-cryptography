--[=[
	Number Theoretic Transform (NTT) for ML-DSA

	Implements forward and inverse NTT over Z_q[X]/(X^256 + 1) with
	q = 8380417 using precomputed signed root tables.

	Example usage:
		local Poly = buffer.create(256 * 4)
		NTT.ForwardNTTWithOffset(Poly, 0)
		NTT.InverseNTTWithOffset(Poly, 0)
--]=]

--!strict
--!optimize 2
--!native

local Q = 8380417
local INV_N = -32736
local INV_Q = 1 / Q
local BIAS = 2 ^ -24
local IZ01_SCALED = 46690

local NZ01 = -3572223
local NZ02 = 3765607
local NZ03 = 3761513
local NZ04 = -3201494
local NZ05 = -2883726
local NZ06 = -3145678
local NZ07 = -3201430
local NZ08 = -601683
local NZ09 = 3542485
local NZ10 = 2682288
local NZ11 = 2129892
local NZ12 = 3764867
local NZ13 = -1005239
local NZ14 = 557458
local NZ15 = -1221177
local IZ02 = -3765607
local IZ03 = -3761513
local IZ04 = 3201494
local IZ05 = 2883726
local IZ06 = 3145678
local IZ07 = 3201430
local IZ08 = 601683
local IZ09 = -3542485
local IZ10 = -2682288
local IZ11 = -2129892
local IZ12 = -3764867
local IZ13 = 1005239
local IZ14 = -557458
local IZ15 = 1221177

local ZETA_EXP: buffer = buffer.fromstring("\001\000\000\000\001\126\201\255\103\117\057\000\105\101\057\000\z
	\042\038\207\255\114\255\211\255\050\000\208\255\106\038\207\255\z
	\173\209\246\255\213\013\054\000\176\237\040\000\228\127\032\000\z
	\131\114\057\000\073\169\240\255\146\129\008\000\199\093\237\255\z
	\147\146\204\255\179\000\194\255\210\163\040\000\137\114\230\255\z
	\166\056\202\255\051\096\249\255\238\082\010\000\128\157\235\255\z
	\028\191\206\255\119\040\026\000\223\113\037\000\238\073\022\000\z
	\188\049\246\255\182\075\201\255\151\246\042\000\213\216\034\000\z
	\042\247\054\000\030\145\048\000\063\209\041\000\114\070\201\255\z
	\094\136\208\255\162\016\032\000\247\135\056\000\195\178\017\000\z
	\164\003\006\000\237\043\014\000\044\183\016\000\052\127\202\255\z
	\021\157\031\000\211\172\194\255\244\119\049\000\018\230\032\000\z
	\029\028\052\000\115\216\026\000\128\134\243\255\062\117\201\255\z
	\246\082\057\000\073\118\226\255\004\205\229\255\027\186\195\255\z
	\094\202\211\255\034\182\048\000\056\127\008\000\109\014\059\000\z
	\218\131\044\000\110\073\028\000\043\014\051\000\112\091\028\000\z
	\241\227\046\000\185\126\019\000\047\201\215\255\239\198\058\000\z
	\076\213\063\000\233\210\206\255\224\094\208\255\116\209\251\255\z
	\180\072\038\000\086\242\030\000\162\144\029\000\211\198\197\255\z
	\155\229\042\000\155\120\210\255\244\017\239\255\136\114\063\000\z
	\002\081\023\000\089\093\007\000\186\135\017\000\168\204\210\255\z
	\157\094\247\255\216\150\002\000\236\146\037\000\017\031\205\255\z
	\231\108\192\255\129\197\202\255\230\084\030\000\192\054\207\255\z
	\121\126\026\000\143\151\003\000\022\104\206\255\089\184\049\000\z
	\203\164\216\255\039\072\027\000\207\131\219\255\121\152\221\255\z
	\094\034\053\000\125\044\192\255\208\041\236\255\049\245\219\255\z
	\210\228\235\255\203\142\037\000\076\083\046\000\108\122\009\000\z
	\032\136\059\000\091\072\237\255\248\164\044\000\170\124\051\000\z
	\160\178\020\000\053\165\213\255\134\241\040\000\092\153\213\255\z
	\111\022\203\255\134\074\035\000\037\008\246\255\101\254\248\255\z
	\140\082\005\000\088\255\250\255\023\110\015\000\217\019\220\255\z
	\125\187\197\255\051\171\226\255\202\222\221\255\123\158\026\000\z
	\217\006\000\000\196\119\226\255\059\107\215\255\238\200\233\255\z
	\056\152\040\000\253\213\228\255\244\024\255\255\120\078\042\000\z
	\035\010\018\000\168\084\001\000\255\183\009\000\134\126\195\255\z
	\247\159\195\255\179\245\220\255\077\224\205\255\174\072\199\255\z
	\092\147\255\255\013\141\012\000\213\102\015\000\127\141\218\255\z
	\151\203\225\255\150\093\024\000\048\159\195\255\151\162\198\255\z
	\095\073\230\255\120\245\203\255\006\222\040\000\140\125\198\255\z
	\226\208\201\255\052\180\009\000\178\045\252\255\175\136\218\255\z
	\168\187\192\255\212\243\228\255\042\118\033\000\144\165\229\255\z
	\057\110\036\000\154\227\200\255\088\231\251\255\088\120\207\255\z
	\178\045\057\000\035\009\035\000\103\235\018\000\241\109\197\255\z
	\028\195\048\000\036\084\040\000\046\035\019\000\127\207\255\255\z
	\203\191\045\000\011\042\002\000\043\163\254\255\122\088\038\000\z
	\116\083\235\255\118\091\009\000\203\001\236\255\029\038\222\255\z
	\012\000\249\255\054\172\226\255\004\166\061\000\059\005\203\255\z
	\104\029\031\000\186\080\227\255\183\129\243\255\107\192\222\255\z
	\198\058\231\255\198\031\032\000\254\196\219\255\113\247\224\255\z
	\001\242\008\000\035\000\238\255\109\014\008\000\141\035\214\255\z
	\135\118\233\255\062\109\030\000\189\003\038\000\249\189\234\255\z
	\023\192\007\000\211\223\237\255\188\240\244\255\226\001\228\255\z
	\114\181\209\255\012\214\250\255\186\103\040\000\212\236\045\000\z
	\139\033\216\255\245\076\063\000\009\112\011\000\034\158\194\255\z
	\055\189\060\000\051\051\039\000\086\089\231\255\093\075\026\000\z
	\038\105\025\000\006\242\030\000\078\193\017\000\199\150\204\255\z
	\047\244\060\000\153\209\255\255\107\022\235\255\105\022\046\000\z
	\214\082\051\000\096\071\003\000\096\082\008\000\119\062\244\255\z
	\022\099\047\000\016\042\239\255\241\192\007\000\010\141\247\255\z
	\240\031\013\000\036\088\052\000\212\035\002\000\088\229\232\255\z
	\132\168\222\255\050\170\047\000\101\252\035\000\065\137\222\255\z
	\236\000\210\255\178\205\229\255\230\165\044\000\253\001\250\255\z
	\099\096\251\255\221\225\053\000\171\090\195\255\221\106\198\255\z
	\020\254\028\000\205\017\244\255\014\023\016\000\214\214\244\255")
local ZETA_NEG_EXP: buffer = buffer.fromstring("\255\255\255\255\255\129\054\000\153\138\198\255\151\154\198\255\z
	\214\217\048\000\142\000\044\000\206\255\047\000\150\217\048\000\z
	\083\046\009\000\043\242\201\255\080\018\215\255\028\128\223\255\z
	\125\141\198\255\183\086\015\000\110\126\247\255\057\162\018\000\z
	\109\109\051\000\077\255\061\000\046\092\215\255\119\141\025\000\z
	\090\199\053\000\205\159\006\000\018\173\245\255\128\098\020\000\z
	\228\064\049\000\137\215\229\255\033\142\218\255\018\182\233\255\z
	\068\206\009\000\074\180\054\000\105\009\213\255\043\039\221\255\z
	\214\008\201\255\226\110\207\255\193\046\214\255\142\185\054\000\z
	\162\119\047\000\094\239\223\255\009\120\199\255\061\077\238\255\z
	\092\252\249\255\019\212\241\255\212\072\239\255\204\128\053\000\z
	\235\098\224\255\045\083\061\000\012\136\206\255\238\025\223\255\z
	\227\227\203\255\141\039\229\255\128\121\012\000\194\138\054\000\z
	\010\173\198\255\183\137\029\000\252\050\026\000\229\069\060\000\z
	\162\053\044\000\222\073\207\255\200\128\247\255\147\241\196\255\z
	\038\124\211\255\146\182\227\255\213\241\204\255\144\164\227\255\z
	\015\028\209\255\071\129\236\255\209\054\040\000\017\057\197\255\z
	\180\042\192\255\023\045\049\000\032\161\047\000\140\046\004\000\z
	\076\183\217\255\170\013\225\255\094\111\226\255\045\057\058\000\z
	\101\026\213\255\101\135\045\000\012\238\016\000\120\141\192\255\z
	\254\174\232\255\167\162\248\255\070\120\238\255\088\051\045\000\z
	\099\161\008\000\040\105\253\255\020\109\218\255\239\224\050\000\z
	\025\147\063\000\127\058\053\000\026\171\225\255\064\201\048\000\z
	\135\129\229\255\113\104\252\255\234\151\049\000\167\071\206\255\z
	\053\091\039\000\217\183\228\255\049\124\036\000\135\103\034\000\z
	\162\221\202\255\131\211\063\000\048\214\019\000\207\010\036\000\z
	\046\027\020\000\053\113\218\255\180\172\209\255\148\133\246\255\z
	\224\119\196\255\165\183\018\000\008\091\211\255\086\131\204\255\z
	\096\077\235\255\203\090\042\000\122\014\215\255\164\102\042\000\z
	\145\233\052\000\122\181\220\255\219\247\009\000\155\001\007\000\z
	\116\173\250\255\168\000\005\000\233\145\240\255\039\236\035\000\z
	\131\068\058\000\205\084\029\000\054\033\034\000\133\097\229\255\z
	\039\249\255\255\060\136\029\000\197\148\040\000\018\055\022\000\z
	\200\103\215\255\003\042\027\000\012\231\000\000\136\177\213\255\z
	\221\245\237\255\088\171\254\255\001\072\246\255\122\129\060\000\z
	\009\096\060\000\077\010\035\000\179\031\050\000\082\183\056\000\z
	\164\108\000\000\243\114\243\255\043\153\240\255\129\114\037\000\z
	\105\052\030\000\106\162\231\255\208\096\060\000\105\093\057\000\z
	\161\182\025\000\136\010\052\000\250\033\215\255\116\130\057\000\z
	\030\047\054\000\204\075\246\255\078\210\003\000\081\119\037\000\z
	\088\068\063\000\044\012\027\000\214\137\222\255\112\090\026\000\z
	\199\145\219\255\102\028\055\000\168\024\004\000\168\135\048\000\z
	\078\210\198\255\221\246\220\255\153\020\237\255\015\146\058\000\z
	\228\060\207\255\220\171\215\255\210\220\236\255\129\048\000\000\z
	\053\064\210\255\245\213\253\255\213\092\001\000\134\167\217\255\z
	\140\172\020\000\138\164\246\255\053\254\019\000\227\217\033\000\z
	\244\255\006\000\202\083\029\000\252\089\194\255\197\250\052\000\z
	\152\226\224\255\070\175\028\000\073\126\012\000\149\063\033\000\z
	\058\197\024\000\058\224\223\255\002\059\036\000\143\008\031\000\z
	\255\013\247\255\221\255\017\000\147\241\247\255\115\220\041\000\z
	\121\137\022\000\194\146\225\255\067\252\217\255\007\066\021\000\z
	\233\063\248\255\045\032\018\000\068\015\011\000\030\254\027\000\z
	\142\074\046\000\244\041\005\000\070\152\215\255\044\019\210\255\z
	\117\222\039\000\011\179\192\255\247\143\244\255\222\097\061\000\z
	\201\066\195\255\205\204\216\255\170\166\024\000\163\180\229\255\z
	\218\150\230\255\250\013\225\255\178\062\238\255\057\105\051\000\z
	\209\011\195\255\103\046\000\000\149\233\020\000\151\233\209\255\z
	\042\173\204\255\160\184\252\255\160\173\247\255\137\193\011\000\z
	\234\156\208\255\240\213\016\000\015\063\248\255\246\114\008\000\z
	\016\224\242\255\220\167\203\255\044\220\253\255\168\026\023\000\z
	\124\087\033\000\206\085\208\255\155\003\220\255\191\118\033\000\z
	\020\255\045\000\078\050\026\000\026\090\211\255\003\254\005\000\z
	\157\159\004\000\035\030\202\255\085\165\060\000\035\149\057\000\z
	\236\001\227\255\051\238\011\000\242\232\239\255\042\041\011\000")

local function ModQ(Value: number): number
	return Value - math.floor(Value * INV_Q + BIAS) * Q
end

local Ntt = {}

function Ntt.ForwardNTTWithOffset(Poly: buffer, BaseOffset: number): ()
	local Zeta = ZETA_EXP
	for Group = 0, 60, 4 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 64)
		local C02 = buffer.readu32(Poly, Base + 128)
		local C03 = buffer.readu32(Poly, Base + 192)
		local C04 = buffer.readu32(Poly, Base + 256)
		local C05 = buffer.readu32(Poly, Base + 320)
		local C06 = buffer.readu32(Poly, Base + 384)
		local C07 = buffer.readu32(Poly, Base + 448)
		local C08 = buffer.readu32(Poly, Base + 512)
		local C09 = buffer.readu32(Poly, Base + 576)
		local C10 = buffer.readu32(Poly, Base + 640)
		local C11 = buffer.readu32(Poly, Base + 704)
		local C12 = buffer.readu32(Poly, Base + 768)
		local C13 = buffer.readu32(Poly, Base + 832)
		local C14 = buffer.readu32(Poly, Base + 896)
		local C15 = buffer.readu32(Poly, Base + 960)
		do local Tmp = ModQ(C08 * NZ01); C08 = C00 - Tmp; C00 += Tmp end
		do local Tmp = ModQ(C09 * NZ01); C09 = C01 - Tmp; C01 += Tmp end
		do local Tmp = ModQ(C10 * NZ01); C10 = C02 - Tmp; C02 += Tmp end
		do local Tmp = ModQ(C11 * NZ01); C11 = C03 - Tmp; C03 += Tmp end
		do local Tmp = ModQ(C12 * NZ01); C12 = C04 - Tmp; C04 += Tmp end
		do local Tmp = ModQ(C13 * NZ01); C13 = C05 - Tmp; C05 += Tmp end
		do local Tmp = ModQ(C14 * NZ01); C14 = C06 - Tmp; C06 += Tmp end
		do local Tmp = ModQ(C15 * NZ01); C15 = C07 - Tmp; C07 += Tmp end
		do local Tmp = ModQ(C04 * NZ02); C04 = C00 - Tmp; C00 += Tmp end
		do local Tmp = ModQ(C05 * NZ02); C05 = C01 - Tmp; C01 += Tmp end
		do local Tmp = ModQ(C06 * NZ02); C06 = C02 - Tmp; C02 += Tmp end
		do local Tmp = ModQ(C07 * NZ02); C07 = C03 - Tmp; C03 += Tmp end
		do local Tmp = ModQ(C12 * NZ03); C12 = C08 - Tmp; C08 += Tmp end
		do local Tmp = ModQ(C13 * NZ03); C13 = C09 - Tmp; C09 += Tmp end
		do local Tmp = ModQ(C14 * NZ03); C14 = C10 - Tmp; C10 += Tmp end
		do local Tmp = ModQ(C15 * NZ03); C15 = C11 - Tmp; C11 += Tmp end
		do local Tmp = ModQ(C02 * NZ04); C02 = C00 - Tmp; C00 += Tmp end
		do local Tmp = ModQ(C03 * NZ04); C03 = C01 - Tmp; C01 += Tmp end
		do local Tmp = ModQ(C06 * NZ05); C06 = C04 - Tmp; C04 += Tmp end
		do local Tmp = ModQ(C07 * NZ05); C07 = C05 - Tmp; C05 += Tmp end
		do local Tmp = ModQ(C10 * NZ06); C10 = C08 - Tmp; C08 += Tmp end
		do local Tmp = ModQ(C11 * NZ06); C11 = C09 - Tmp; C09 += Tmp end
		do local Tmp = ModQ(C14 * NZ07); C14 = C12 - Tmp; C12 += Tmp end
		do local Tmp = ModQ(C15 * NZ07); C15 = C13 - Tmp; C13 += Tmp end
		do local Tmp = ModQ(C01 * NZ08); C01 = C00 - Tmp; C00 += Tmp end
		do local Tmp = ModQ(C03 * NZ09); C03 = C02 - Tmp; C02 += Tmp end
		do local Tmp = ModQ(C05 * NZ10); C05 = C04 - Tmp; C04 += Tmp end
		do local Tmp = ModQ(C07 * NZ11); C07 = C06 - Tmp; C06 += Tmp end
		do local Tmp = ModQ(C09 * NZ12); C09 = C08 - Tmp; C08 += Tmp end
		do local Tmp = ModQ(C11 * NZ13); C11 = C10 - Tmp; C10 += Tmp end
		do local Tmp = ModQ(C13 * NZ14); C13 = C12 - Tmp; C12 += Tmp end
		do local Tmp = ModQ(C15 * NZ15); C15 = C14 - Tmp; C14 += Tmp end
		buffer.writeu32(Poly, Base + 0, ModQ(C00))
		buffer.writeu32(Poly, Base + 64, ModQ(C01))
		buffer.writeu32(Poly, Base + 128, ModQ(C02))
		buffer.writeu32(Poly, Base + 192, ModQ(C03))
		buffer.writeu32(Poly, Base + 256, ModQ(C04))
		buffer.writeu32(Poly, Base + 320, ModQ(C05))
		buffer.writeu32(Poly, Base + 384, ModQ(C06))
		buffer.writeu32(Poly, Base + 448, ModQ(C07))
		buffer.writeu32(Poly, Base + 512, ModQ(C08))
		buffer.writeu32(Poly, Base + 576, ModQ(C09))
		buffer.writeu32(Poly, Base + 640, ModQ(C10))
		buffer.writeu32(Poly, Base + 704, ModQ(C11))
		buffer.writeu32(Poly, Base + 768, ModQ(C12))
		buffer.writeu32(Poly, Base + 832, ModQ(C13))
		buffer.writeu32(Poly, Base + 896, ModQ(C14))
		buffer.writeu32(Poly, Base + 960, ModQ(C15))
	end
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 64
		local Y0 = buffer.readi32(Zeta, 64 + Block * 4)
		local Y1 = buffer.readi32(Zeta, 128 + Block * 8)
		local Y2 = buffer.readi32(Zeta, 132 + Block * 8)
		local X0 = buffer.readi32(Zeta, 256 + Block * 16)
		local X1 = buffer.readi32(Zeta, 260 + Block * 16)
		local X2 = buffer.readi32(Zeta, 264 + Block * 16)
		local X3 = buffer.readi32(Zeta, 268 + Block * 16)
		local V0 = buffer.readi32(Zeta, 512 + Block * 32)
		local V1 = buffer.readi32(Zeta, 516 + Block * 32)
		local V2 = buffer.readi32(Zeta, 520 + Block * 32)
		local V3 = buffer.readi32(Zeta, 524 + Block * 32)
		local V4 = buffer.readi32(Zeta, 528 + Block * 32)
		local V5 = buffer.readi32(Zeta, 532 + Block * 32)
		local V6 = buffer.readi32(Zeta, 536 + Block * 32)
		local V7 = buffer.readi32(Zeta, 540 + Block * 32)
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 4)
		local C02 = buffer.readu32(Poly, Base + 8)
		local C03 = buffer.readu32(Poly, Base + 12)
		local C04 = buffer.readu32(Poly, Base + 16)
		local C05 = buffer.readu32(Poly, Base + 20)
		local C06 = buffer.readu32(Poly, Base + 24)
		local C07 = buffer.readu32(Poly, Base + 28)
		local C08 = buffer.readu32(Poly, Base + 32)
		local C09 = buffer.readu32(Poly, Base + 36)
		local C10 = buffer.readu32(Poly, Base + 40)
		local C11 = buffer.readu32(Poly, Base + 44)
		local C12 = buffer.readu32(Poly, Base + 48)
		local C13 = buffer.readu32(Poly, Base + 52)
		local C14 = buffer.readu32(Poly, Base + 56)
		local C15 = buffer.readu32(Poly, Base + 60)
		do local Tmp = ModQ(C08 * Y0); C08 = C00 - Tmp; C00 += Tmp end
		do local Tmp = ModQ(C09 * Y0); C09 = C01 - Tmp; C01 += Tmp end
		do local Tmp = ModQ(C10 * Y0); C10 = C02 - Tmp; C02 += Tmp end
		do local Tmp = ModQ(C11 * Y0); C11 = C03 - Tmp; C03 += Tmp end
		do local Tmp = ModQ(C12 * Y0); C12 = C04 - Tmp; C04 += Tmp end
		do local Tmp = ModQ(C13 * Y0); C13 = C05 - Tmp; C05 += Tmp end
		do local Tmp = ModQ(C14 * Y0); C14 = C06 - Tmp; C06 += Tmp end
		do local Tmp = ModQ(C15 * Y0); C15 = C07 - Tmp; C07 += Tmp end
		do local Tmp = ModQ(C04 * Y1); C04 = C00 - Tmp; C00 += Tmp end
		do local Tmp = ModQ(C05 * Y1); C05 = C01 - Tmp; C01 += Tmp end
		do local Tmp = ModQ(C06 * Y1); C06 = C02 - Tmp; C02 += Tmp end
		do local Tmp = ModQ(C07 * Y1); C07 = C03 - Tmp; C03 += Tmp end
		do local Tmp = ModQ(C12 * Y2); C12 = C08 - Tmp; C08 += Tmp end
		do local Tmp = ModQ(C13 * Y2); C13 = C09 - Tmp; C09 += Tmp end
		do local Tmp = ModQ(C14 * Y2); C14 = C10 - Tmp; C10 += Tmp end
		do local Tmp = ModQ(C15 * Y2); C15 = C11 - Tmp; C11 += Tmp end
		do local Tmp = ModQ(C02 * X0); C02 = C00 - Tmp; C00 += Tmp end
		do local Tmp = ModQ(C03 * X0); C03 = C01 - Tmp; C01 += Tmp end
		do local Tmp = ModQ(C06 * X1); C06 = C04 - Tmp; C04 += Tmp end
		do local Tmp = ModQ(C07 * X1); C07 = C05 - Tmp; C05 += Tmp end
		do local Tmp = ModQ(C10 * X2); C10 = C08 - Tmp; C08 += Tmp end
		do local Tmp = ModQ(C11 * X2); C11 = C09 - Tmp; C09 += Tmp end
		do local Tmp = ModQ(C14 * X3); C14 = C12 - Tmp; C12 += Tmp end
		do local Tmp = ModQ(C15 * X3); C15 = C13 - Tmp; C13 += Tmp end
		do local Tmp = ModQ(C01 * V0); C01 = C00 - Tmp; C00 += Tmp end
		do local Tmp = ModQ(C03 * V1); C03 = C02 - Tmp; C02 += Tmp end
		do local Tmp = ModQ(C05 * V2); C05 = C04 - Tmp; C04 += Tmp end
		do local Tmp = ModQ(C07 * V3); C07 = C06 - Tmp; C06 += Tmp end
		do local Tmp = ModQ(C09 * V4); C09 = C08 - Tmp; C08 += Tmp end
		do local Tmp = ModQ(C11 * V5); C11 = C10 - Tmp; C10 += Tmp end
		do local Tmp = ModQ(C13 * V6); C13 = C12 - Tmp; C12 += Tmp end
		do local Tmp = ModQ(C15 * V7); C15 = C14 - Tmp; C14 += Tmp end
		buffer.writeu32(Poly, Base + 0, ModQ(C00))
		buffer.writeu32(Poly, Base + 4, ModQ(C01))
		buffer.writeu32(Poly, Base + 8, ModQ(C02))
		buffer.writeu32(Poly, Base + 12, ModQ(C03))
		buffer.writeu32(Poly, Base + 16, ModQ(C04))
		buffer.writeu32(Poly, Base + 20, ModQ(C05))
		buffer.writeu32(Poly, Base + 24, ModQ(C06))
		buffer.writeu32(Poly, Base + 28, ModQ(C07))
		buffer.writeu32(Poly, Base + 32, ModQ(C08))
		buffer.writeu32(Poly, Base + 36, ModQ(C09))
		buffer.writeu32(Poly, Base + 40, ModQ(C10))
		buffer.writeu32(Poly, Base + 44, ModQ(C11))
		buffer.writeu32(Poly, Base + 48, ModQ(C12))
		buffer.writeu32(Poly, Base + 52, ModQ(C13))
		buffer.writeu32(Poly, Base + 56, ModQ(C14))
		buffer.writeu32(Poly, Base + 60, ModQ(C15))
	end
end

function Ntt.InverseNTTWithOffset(Poly: buffer, BaseOffset: number): ()
	local Zeta = ZETA_NEG_EXP
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 64
		local V0 = buffer.readi32(Zeta, 1020 - Block * 32)
		local V1 = buffer.readi32(Zeta, 1016 - Block * 32)
		local V2 = buffer.readi32(Zeta, 1012 - Block * 32)
		local V3 = buffer.readi32(Zeta, 1008 - Block * 32)
		local V4 = buffer.readi32(Zeta, 1004 - Block * 32)
		local V5 = buffer.readi32(Zeta, 1000 - Block * 32)
		local V6 = buffer.readi32(Zeta, 996 - Block * 32)
		local V7 = buffer.readi32(Zeta, 992 - Block * 32)
		local X0 = buffer.readi32(Zeta, 508 - Block * 16)
		local X1 = buffer.readi32(Zeta, 504 - Block * 16)
		local X2 = buffer.readi32(Zeta, 500 - Block * 16)
		local X3 = buffer.readi32(Zeta, 496 - Block * 16)
		local Y1 = buffer.readi32(Zeta, 252 - Block * 8)
		local Y2 = buffer.readi32(Zeta, 248 - Block * 8)
		local Y0 = buffer.readi32(Zeta, 124 - Block * 4)
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 4)
		local C02 = buffer.readu32(Poly, Base + 8)
		local C03 = buffer.readu32(Poly, Base + 12)
		local C04 = buffer.readu32(Poly, Base + 16)
		local C05 = buffer.readu32(Poly, Base + 20)
		local C06 = buffer.readu32(Poly, Base + 24)
		local C07 = buffer.readu32(Poly, Base + 28)
		local C08 = buffer.readu32(Poly, Base + 32)
		local C09 = buffer.readu32(Poly, Base + 36)
		local C10 = buffer.readu32(Poly, Base + 40)
		local C11 = buffer.readu32(Poly, Base + 44)
		local C12 = buffer.readu32(Poly, Base + 48)
		local C13 = buffer.readu32(Poly, Base + 52)
		local C14 = buffer.readu32(Poly, Base + 56)
		local C15 = buffer.readu32(Poly, Base + 60)
		do local Sum = C00 + C01; C01 = ModQ((C00 - C01) * V0); C00 = Sum end
		do local Sum = C02 + C03; C03 = ModQ((C02 - C03) * V1); C02 = Sum end
		do local Sum = C04 + C05; C05 = ModQ((C04 - C05) * V2); C04 = Sum end
		do local Sum = C06 + C07; C07 = ModQ((C06 - C07) * V3); C06 = Sum end
		do local Sum = C08 + C09; C09 = ModQ((C08 - C09) * V4); C08 = Sum end
		do local Sum = C10 + C11; C11 = ModQ((C10 - C11) * V5); C10 = Sum end
		do local Sum = C12 + C13; C13 = ModQ((C12 - C13) * V6); C12 = Sum end
		do local Sum = C14 + C15; C15 = ModQ((C14 - C15) * V7); C14 = Sum end
		do local Sum = C00 + C02; C02 = ModQ((C00 - C02) * X0); C00 = Sum end
		do local Sum = C01 + C03; C03 = ModQ((C01 - C03) * X0); C01 = Sum end
		do local Sum = C04 + C06; C06 = ModQ((C04 - C06) * X1); C04 = Sum end
		do local Sum = C05 + C07; C07 = ModQ((C05 - C07) * X1); C05 = Sum end
		do local Sum = C08 + C10; C10 = ModQ((C08 - C10) * X2); C08 = Sum end
		do local Sum = C09 + C11; C11 = ModQ((C09 - C11) * X2); C09 = Sum end
		do local Sum = C12 + C14; C14 = ModQ((C12 - C14) * X3); C12 = Sum end
		do local Sum = C13 + C15; C15 = ModQ((C13 - C15) * X3); C13 = Sum end
		do local Sum = C00 + C04; C04 = ModQ((C00 - C04) * Y1); C00 = Sum end
		do local Sum = C01 + C05; C05 = ModQ((C01 - C05) * Y1); C01 = Sum end
		do local Sum = C02 + C06; C06 = ModQ((C02 - C06) * Y1); C02 = Sum end
		do local Sum = C03 + C07; C07 = ModQ((C03 - C07) * Y1); C03 = Sum end
		do local Sum = C08 + C12; C12 = ModQ((C08 - C12) * Y2); C08 = Sum end
		do local Sum = C09 + C13; C13 = ModQ((C09 - C13) * Y2); C09 = Sum end
		do local Sum = C10 + C14; C14 = ModQ((C10 - C14) * Y2); C10 = Sum end
		do local Sum = C11 + C15; C15 = ModQ((C11 - C15) * Y2); C11 = Sum end
		do local Sum = C00 + C08; C08 = ModQ((C00 - C08) * Y0); C00 = Sum end
		do local Sum = C01 + C09; C09 = ModQ((C01 - C09) * Y0); C01 = Sum end
		do local Sum = C02 + C10; C10 = ModQ((C02 - C10) * Y0); C02 = Sum end
		do local Sum = C03 + C11; C11 = ModQ((C03 - C11) * Y0); C03 = Sum end
		do local Sum = C04 + C12; C12 = ModQ((C04 - C12) * Y0); C04 = Sum end
		do local Sum = C05 + C13; C13 = ModQ((C05 - C13) * Y0); C05 = Sum end
		do local Sum = C06 + C14; C14 = ModQ((C06 - C14) * Y0); C06 = Sum end
		do local Sum = C07 + C15; C15 = ModQ((C07 - C15) * Y0); C07 = Sum end
		buffer.writeu32(Poly, Base + 0, C00)
		buffer.writeu32(Poly, Base + 4, C01)
		buffer.writeu32(Poly, Base + 8, C02)
		buffer.writeu32(Poly, Base + 12, C03)
		buffer.writeu32(Poly, Base + 16, C04)
		buffer.writeu32(Poly, Base + 20, C05)
		buffer.writeu32(Poly, Base + 24, C06)
		buffer.writeu32(Poly, Base + 28, C07)
		buffer.writeu32(Poly, Base + 32, C08)
		buffer.writeu32(Poly, Base + 36, C09)
		buffer.writeu32(Poly, Base + 40, C10)
		buffer.writeu32(Poly, Base + 44, C11)
		buffer.writeu32(Poly, Base + 48, C12)
		buffer.writeu32(Poly, Base + 52, C13)
		buffer.writeu32(Poly, Base + 56, C14)
		buffer.writeu32(Poly, Base + 60, C15)
	end
	for Group = 0, 60, 4 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 64)
		local C02 = buffer.readu32(Poly, Base + 128)
		local C03 = buffer.readu32(Poly, Base + 192)
		local C04 = buffer.readu32(Poly, Base + 256)
		local C05 = buffer.readu32(Poly, Base + 320)
		local C06 = buffer.readu32(Poly, Base + 384)
		local C07 = buffer.readu32(Poly, Base + 448)
		local C08 = buffer.readu32(Poly, Base + 512)
		local C09 = buffer.readu32(Poly, Base + 576)
		local C10 = buffer.readu32(Poly, Base + 640)
		local C11 = buffer.readu32(Poly, Base + 704)
		local C12 = buffer.readu32(Poly, Base + 768)
		local C13 = buffer.readu32(Poly, Base + 832)
		local C14 = buffer.readu32(Poly, Base + 896)
		local C15 = buffer.readu32(Poly, Base + 960)
		do local Sum = C00 + C01; C01 = ModQ((C00 - C01) * IZ15); C00 = Sum end
		do local Sum = C02 + C03; C03 = ModQ((C02 - C03) * IZ14); C02 = Sum end
		do local Sum = C04 + C05; C05 = ModQ((C04 - C05) * IZ13); C04 = Sum end
		do local Sum = C06 + C07; C07 = ModQ((C06 - C07) * IZ12); C06 = Sum end
		do local Sum = C08 + C09; C09 = ModQ((C08 - C09) * IZ11); C08 = Sum end
		do local Sum = C10 + C11; C11 = ModQ((C10 - C11) * IZ10); C10 = Sum end
		do local Sum = C12 + C13; C13 = ModQ((C12 - C13) * IZ09); C12 = Sum end
		do local Sum = C14 + C15; C15 = ModQ((C14 - C15) * IZ08); C14 = Sum end
		do local Sum = C00 + C02; C02 = ModQ((C00 - C02) * IZ07); C00 = Sum end
		do local Sum = C01 + C03; C03 = ModQ((C01 - C03) * IZ07); C01 = Sum end
		do local Sum = C04 + C06; C06 = ModQ((C04 - C06) * IZ06); C04 = Sum end
		do local Sum = C05 + C07; C07 = ModQ((C05 - C07) * IZ06); C05 = Sum end
		do local Sum = C08 + C10; C10 = ModQ((C08 - C10) * IZ05); C08 = Sum end
		do local Sum = C09 + C11; C11 = ModQ((C09 - C11) * IZ05); C09 = Sum end
		do local Sum = C12 + C14; C14 = ModQ((C12 - C14) * IZ04); C12 = Sum end
		do local Sum = C13 + C15; C15 = ModQ((C13 - C15) * IZ04); C13 = Sum end
		do local Sum = C00 + C04; C04 = ModQ((C00 - C04) * IZ03); C00 = ModQ(Sum) end
		do local Sum = C01 + C05; C05 = ModQ((C01 - C05) * IZ03); C01 = ModQ(Sum) end
		do local Sum = C02 + C06; C06 = ModQ((C02 - C06) * IZ03); C02 = ModQ(Sum) end
		do local Sum = C03 + C07; C07 = ModQ((C03 - C07) * IZ03); C03 = ModQ(Sum) end
		do local Sum = C08 + C12; C12 = ModQ((C08 - C12) * IZ02); C08 = ModQ(Sum) end
		do local Sum = C09 + C13; C13 = ModQ((C09 - C13) * IZ02); C09 = ModQ(Sum) end
		do local Sum = C10 + C14; C14 = ModQ((C10 - C14) * IZ02); C10 = ModQ(Sum) end
		do local Sum = C11 + C15; C15 = ModQ((C11 - C15) * IZ02); C11 = ModQ(Sum) end
		do local Sum = C00 + C08; C08 = ModQ((C00 - C08) * IZ01_SCALED); C00 = ModQ(Sum * INV_N) end
		do local Sum = C01 + C09; C09 = ModQ((C01 - C09) * IZ01_SCALED); C01 = ModQ(Sum * INV_N) end
		do local Sum = C02 + C10; C10 = ModQ((C02 - C10) * IZ01_SCALED); C02 = ModQ(Sum * INV_N) end
		do local Sum = C03 + C11; C11 = ModQ((C03 - C11) * IZ01_SCALED); C03 = ModQ(Sum * INV_N) end
		do local Sum = C04 + C12; C12 = ModQ((C04 - C12) * IZ01_SCALED); C04 = ModQ(Sum * INV_N) end
		do local Sum = C05 + C13; C13 = ModQ((C05 - C13) * IZ01_SCALED); C05 = ModQ(Sum * INV_N) end
		do local Sum = C06 + C14; C14 = ModQ((C06 - C14) * IZ01_SCALED); C06 = ModQ(Sum * INV_N) end
		do local Sum = C07 + C15; C15 = ModQ((C07 - C15) * IZ01_SCALED); C07 = ModQ(Sum * INV_N) end
		buffer.writeu32(Poly, Base + 0, C00)
		buffer.writeu32(Poly, Base + 64, C01)
		buffer.writeu32(Poly, Base + 128, C02)
		buffer.writeu32(Poly, Base + 192, C03)
		buffer.writeu32(Poly, Base + 256, C04)
		buffer.writeu32(Poly, Base + 320, C05)
		buffer.writeu32(Poly, Base + 384, C06)
		buffer.writeu32(Poly, Base + 448, C07)
		buffer.writeu32(Poly, Base + 512, C08)
		buffer.writeu32(Poly, Base + 576, C09)
		buffer.writeu32(Poly, Base + 640, C10)
		buffer.writeu32(Poly, Base + 704, C11)
		buffer.writeu32(Poly, Base + 768, C12)
		buffer.writeu32(Poly, Base + 832, C13)
		buffer.writeu32(Poly, Base + 896, C14)
		buffer.writeu32(Poly, Base + 960, C15)
	end
end

function Ntt.InverseNTTProduct(Factor: buffer, Source: buffer, SourceOffset: number, Poly: buffer, BaseOffset: number): ()
	local Zeta = ZETA_NEG_EXP
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 64
		local FactorBase = Block * 64
		local SourceBase = SourceOffset + Block * 64
		local V0 = buffer.readi32(Zeta, 1020 - Block * 32)
		local V1 = buffer.readi32(Zeta, 1016 - Block * 32)
		local V2 = buffer.readi32(Zeta, 1012 - Block * 32)
		local V3 = buffer.readi32(Zeta, 1008 - Block * 32)
		local V4 = buffer.readi32(Zeta, 1004 - Block * 32)
		local V5 = buffer.readi32(Zeta, 1000 - Block * 32)
		local V6 = buffer.readi32(Zeta, 996 - Block * 32)
		local V7 = buffer.readi32(Zeta, 992 - Block * 32)
		local X0 = buffer.readi32(Zeta, 508 - Block * 16)
		local X1 = buffer.readi32(Zeta, 504 - Block * 16)
		local X2 = buffer.readi32(Zeta, 500 - Block * 16)
		local X3 = buffer.readi32(Zeta, 496 - Block * 16)
		local Y1 = buffer.readi32(Zeta, 252 - Block * 8)
		local Y2 = buffer.readi32(Zeta, 248 - Block * 8)
		local Y0 = buffer.readi32(Zeta, 124 - Block * 4)
		local C00 = ModQ(buffer.readu32(Factor, FactorBase + 0) * buffer.readu32(Source, SourceBase + 0))
		local C01 = ModQ(buffer.readu32(Factor, FactorBase + 4) * buffer.readu32(Source, SourceBase + 4))
		local C02 = ModQ(buffer.readu32(Factor, FactorBase + 8) * buffer.readu32(Source, SourceBase + 8))
		local C03 = ModQ(buffer.readu32(Factor, FactorBase + 12) * buffer.readu32(Source, SourceBase + 12))
		local C04 = ModQ(buffer.readu32(Factor, FactorBase + 16) * buffer.readu32(Source, SourceBase + 16))
		local C05 = ModQ(buffer.readu32(Factor, FactorBase + 20) * buffer.readu32(Source, SourceBase + 20))
		local C06 = ModQ(buffer.readu32(Factor, FactorBase + 24) * buffer.readu32(Source, SourceBase + 24))
		local C07 = ModQ(buffer.readu32(Factor, FactorBase + 28) * buffer.readu32(Source, SourceBase + 28))
		local C08 = ModQ(buffer.readu32(Factor, FactorBase + 32) * buffer.readu32(Source, SourceBase + 32))
		local C09 = ModQ(buffer.readu32(Factor, FactorBase + 36) * buffer.readu32(Source, SourceBase + 36))
		local C10 = ModQ(buffer.readu32(Factor, FactorBase + 40) * buffer.readu32(Source, SourceBase + 40))
		local C11 = ModQ(buffer.readu32(Factor, FactorBase + 44) * buffer.readu32(Source, SourceBase + 44))
		local C12 = ModQ(buffer.readu32(Factor, FactorBase + 48) * buffer.readu32(Source, SourceBase + 48))
		local C13 = ModQ(buffer.readu32(Factor, FactorBase + 52) * buffer.readu32(Source, SourceBase + 52))
		local C14 = ModQ(buffer.readu32(Factor, FactorBase + 56) * buffer.readu32(Source, SourceBase + 56))
		local C15 = ModQ(buffer.readu32(Factor, FactorBase + 60) * buffer.readu32(Source, SourceBase + 60))
		do local Sum = C00 + C01; C01 = ModQ((C00 - C01) * V0); C00 = Sum end
		do local Sum = C02 + C03; C03 = ModQ((C02 - C03) * V1); C02 = Sum end
		do local Sum = C04 + C05; C05 = ModQ((C04 - C05) * V2); C04 = Sum end
		do local Sum = C06 + C07; C07 = ModQ((C06 - C07) * V3); C06 = Sum end
		do local Sum = C08 + C09; C09 = ModQ((C08 - C09) * V4); C08 = Sum end
		do local Sum = C10 + C11; C11 = ModQ((C10 - C11) * V5); C10 = Sum end
		do local Sum = C12 + C13; C13 = ModQ((C12 - C13) * V6); C12 = Sum end
		do local Sum = C14 + C15; C15 = ModQ((C14 - C15) * V7); C14 = Sum end
		do local Sum = C00 + C02; C02 = ModQ((C00 - C02) * X0); C00 = Sum end
		do local Sum = C01 + C03; C03 = ModQ((C01 - C03) * X0); C01 = Sum end
		do local Sum = C04 + C06; C06 = ModQ((C04 - C06) * X1); C04 = Sum end
		do local Sum = C05 + C07; C07 = ModQ((C05 - C07) * X1); C05 = Sum end
		do local Sum = C08 + C10; C10 = ModQ((C08 - C10) * X2); C08 = Sum end
		do local Sum = C09 + C11; C11 = ModQ((C09 - C11) * X2); C09 = Sum end
		do local Sum = C12 + C14; C14 = ModQ((C12 - C14) * X3); C12 = Sum end
		do local Sum = C13 + C15; C15 = ModQ((C13 - C15) * X3); C13 = Sum end
		do local Sum = C00 + C04; C04 = ModQ((C00 - C04) * Y1); C00 = Sum end
		do local Sum = C01 + C05; C05 = ModQ((C01 - C05) * Y1); C01 = Sum end
		do local Sum = C02 + C06; C06 = ModQ((C02 - C06) * Y1); C02 = Sum end
		do local Sum = C03 + C07; C07 = ModQ((C03 - C07) * Y1); C03 = Sum end
		do local Sum = C08 + C12; C12 = ModQ((C08 - C12) * Y2); C08 = Sum end
		do local Sum = C09 + C13; C13 = ModQ((C09 - C13) * Y2); C09 = Sum end
		do local Sum = C10 + C14; C14 = ModQ((C10 - C14) * Y2); C10 = Sum end
		do local Sum = C11 + C15; C15 = ModQ((C11 - C15) * Y2); C11 = Sum end
		do local Sum = C00 + C08; C08 = ModQ((C00 - C08) * Y0); C00 = Sum end
		do local Sum = C01 + C09; C09 = ModQ((C01 - C09) * Y0); C01 = Sum end
		do local Sum = C02 + C10; C10 = ModQ((C02 - C10) * Y0); C02 = Sum end
		do local Sum = C03 + C11; C11 = ModQ((C03 - C11) * Y0); C03 = Sum end
		do local Sum = C04 + C12; C12 = ModQ((C04 - C12) * Y0); C04 = Sum end
		do local Sum = C05 + C13; C13 = ModQ((C05 - C13) * Y0); C05 = Sum end
		do local Sum = C06 + C14; C14 = ModQ((C06 - C14) * Y0); C06 = Sum end
		do local Sum = C07 + C15; C15 = ModQ((C07 - C15) * Y0); C07 = Sum end
		buffer.writeu32(Poly, Base + 0, C00)
		buffer.writeu32(Poly, Base + 4, C01)
		buffer.writeu32(Poly, Base + 8, C02)
		buffer.writeu32(Poly, Base + 12, C03)
		buffer.writeu32(Poly, Base + 16, C04)
		buffer.writeu32(Poly, Base + 20, C05)
		buffer.writeu32(Poly, Base + 24, C06)
		buffer.writeu32(Poly, Base + 28, C07)
		buffer.writeu32(Poly, Base + 32, C08)
		buffer.writeu32(Poly, Base + 36, C09)
		buffer.writeu32(Poly, Base + 40, C10)
		buffer.writeu32(Poly, Base + 44, C11)
		buffer.writeu32(Poly, Base + 48, C12)
		buffer.writeu32(Poly, Base + 52, C13)
		buffer.writeu32(Poly, Base + 56, C14)
		buffer.writeu32(Poly, Base + 60, C15)
	end
	for Group = 0, 60, 4 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 64)
		local C02 = buffer.readu32(Poly, Base + 128)
		local C03 = buffer.readu32(Poly, Base + 192)
		local C04 = buffer.readu32(Poly, Base + 256)
		local C05 = buffer.readu32(Poly, Base + 320)
		local C06 = buffer.readu32(Poly, Base + 384)
		local C07 = buffer.readu32(Poly, Base + 448)
		local C08 = buffer.readu32(Poly, Base + 512)
		local C09 = buffer.readu32(Poly, Base + 576)
		local C10 = buffer.readu32(Poly, Base + 640)
		local C11 = buffer.readu32(Poly, Base + 704)
		local C12 = buffer.readu32(Poly, Base + 768)
		local C13 = buffer.readu32(Poly, Base + 832)
		local C14 = buffer.readu32(Poly, Base + 896)
		local C15 = buffer.readu32(Poly, Base + 960)
		do local Sum = C00 + C01; C01 = ModQ((C00 - C01) * IZ15); C00 = Sum end
		do local Sum = C02 + C03; C03 = ModQ((C02 - C03) * IZ14); C02 = Sum end
		do local Sum = C04 + C05; C05 = ModQ((C04 - C05) * IZ13); C04 = Sum end
		do local Sum = C06 + C07; C07 = ModQ((C06 - C07) * IZ12); C06 = Sum end
		do local Sum = C08 + C09; C09 = ModQ((C08 - C09) * IZ11); C08 = Sum end
		do local Sum = C10 + C11; C11 = ModQ((C10 - C11) * IZ10); C10 = Sum end
		do local Sum = C12 + C13; C13 = ModQ((C12 - C13) * IZ09); C12 = Sum end
		do local Sum = C14 + C15; C15 = ModQ((C14 - C15) * IZ08); C14 = Sum end
		do local Sum = C00 + C02; C02 = ModQ((C00 - C02) * IZ07); C00 = Sum end
		do local Sum = C01 + C03; C03 = ModQ((C01 - C03) * IZ07); C01 = Sum end
		do local Sum = C04 + C06; C06 = ModQ((C04 - C06) * IZ06); C04 = Sum end
		do local Sum = C05 + C07; C07 = ModQ((C05 - C07) * IZ06); C05 = Sum end
		do local Sum = C08 + C10; C10 = ModQ((C08 - C10) * IZ05); C08 = Sum end
		do local Sum = C09 + C11; C11 = ModQ((C09 - C11) * IZ05); C09 = Sum end
		do local Sum = C12 + C14; C14 = ModQ((C12 - C14) * IZ04); C12 = Sum end
		do local Sum = C13 + C15; C15 = ModQ((C13 - C15) * IZ04); C13 = Sum end
		do local Sum = C00 + C04; C04 = ModQ((C00 - C04) * IZ03); C00 = ModQ(Sum) end
		do local Sum = C01 + C05; C05 = ModQ((C01 - C05) * IZ03); C01 = ModQ(Sum) end
		do local Sum = C02 + C06; C06 = ModQ((C02 - C06) * IZ03); C02 = ModQ(Sum) end
		do local Sum = C03 + C07; C07 = ModQ((C03 - C07) * IZ03); C03 = ModQ(Sum) end
		do local Sum = C08 + C12; C12 = ModQ((C08 - C12) * IZ02); C08 = ModQ(Sum) end
		do local Sum = C09 + C13; C13 = ModQ((C09 - C13) * IZ02); C09 = ModQ(Sum) end
		do local Sum = C10 + C14; C14 = ModQ((C10 - C14) * IZ02); C10 = ModQ(Sum) end
		do local Sum = C11 + C15; C15 = ModQ((C11 - C15) * IZ02); C11 = ModQ(Sum) end
		do local Sum = C00 + C08; C08 = ModQ((C00 - C08) * IZ01_SCALED); C00 = ModQ(Sum * INV_N) end
		do local Sum = C01 + C09; C09 = ModQ((C01 - C09) * IZ01_SCALED); C01 = ModQ(Sum * INV_N) end
		do local Sum = C02 + C10; C10 = ModQ((C02 - C10) * IZ01_SCALED); C02 = ModQ(Sum * INV_N) end
		do local Sum = C03 + C11; C11 = ModQ((C03 - C11) * IZ01_SCALED); C03 = ModQ(Sum * INV_N) end
		do local Sum = C04 + C12; C12 = ModQ((C04 - C12) * IZ01_SCALED); C04 = ModQ(Sum * INV_N) end
		do local Sum = C05 + C13; C13 = ModQ((C05 - C13) * IZ01_SCALED); C05 = ModQ(Sum * INV_N) end
		do local Sum = C06 + C14; C14 = ModQ((C06 - C14) * IZ01_SCALED); C06 = ModQ(Sum * INV_N) end
		do local Sum = C07 + C15; C15 = ModQ((C07 - C15) * IZ01_SCALED); C07 = ModQ(Sum * INV_N) end
		buffer.writeu32(Poly, Base + 0, C00)
		buffer.writeu32(Poly, Base + 64, C01)
		buffer.writeu32(Poly, Base + 128, C02)
		buffer.writeu32(Poly, Base + 192, C03)
		buffer.writeu32(Poly, Base + 256, C04)
		buffer.writeu32(Poly, Base + 320, C05)
		buffer.writeu32(Poly, Base + 384, C06)
		buffer.writeu32(Poly, Base + 448, C07)
		buffer.writeu32(Poly, Base + 512, C08)
		buffer.writeu32(Poly, Base + 576, C09)
		buffer.writeu32(Poly, Base + 640, C10)
		buffer.writeu32(Poly, Base + 704, C11)
		buffer.writeu32(Poly, Base + 768, C12)
		buffer.writeu32(Poly, Base + 832, C13)
		buffer.writeu32(Poly, Base + 896, C14)
		buffer.writeu32(Poly, Base + 960, C15)
	end
end

return Ntt
