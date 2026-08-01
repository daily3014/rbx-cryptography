--!optimize 2
--!native
--! https://github.com/cc-tweaked/CC-Tweaked/blob/66e42e0817484702d3be7ab880e60246097f7ecb/src/main/resources/data/computercraft/lua/rom/modules/main/cc/expect.lua

local function get_type_names(...)
	local types = table.pack(...)
	for i = types.n, 1, -1 do
		if types[i] == "nil" then
			table.remove(types, i)
		end
	end

	if #types <= 1 then
		return tostring(...)
	else
		return table.concat(types, ", ", 1, #types - 1) .. " or " .. types[#types]
	end
end

local function expect(index, value, ...)
	local t = type(value)
	for i = 1, select("#", ...) do
		if t == select(i, ...) then
			return value
		end
	end

	-- t = get_display_type(value, t)

	local type_names = get_type_names(...)
	local name = debug.info(2, "n")

	if name then
		error(("bad argument #%d to '%s' (%s expected, got %s)"):format(index, name, type_names, t), 3)
	else
		error(("bad argument #%d (%s expected, got %s)"):format(index, type_names, t), 3)
	end
end

return { expect = expect }
