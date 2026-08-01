--- High-performance binary packing of integers.
---
--- Remark (and warning):
--- For performance reasons, **the generated functions do not check types,
--- lengths, nor ranges**. You must ensure that the passed arguments are
--- well-formed and respect the format string yourself.

--- (string.pack isn't nil) It's string.pack! It returns string.pack!
--- @param fmt string
--- @return fun(fmt: string, ...: any): string pack string.pack!
--- @return string fmt
local function compilePack(fmt) return string.pack, fmt end

--- (string.pack isn't nil) It's string.unpack! It returns string.unpack!
--- @param fmt string
--- @return fun(fmt: string, str: string, pos: number) unpack string.unpack!
--- @return string fmt
local function compileUnpack(fmt) return string.unpack, fmt end

return {
    compilePack = compilePack,
    compileUnpack = compileUnpack,
}
