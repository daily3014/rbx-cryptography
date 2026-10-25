--!strict

local GROUPS: {[any]: boolean} = setmetatable({}, {__mode = "k"}) :: any

local Lazy = {}

function Lazy.Group(Name: string, Loaders: {[string]: () -> any}): any
	local Members = {}
	local Remaining = 0
	for _ in Loaders do
		Remaining += 1
	end

	local function Load(Self: any, Key: any): any
		local Loader = Loaders[Key]
		if Loader == nil then
			error(`{Name}.{tostring(Key)} does not exist`, 3)
		end

		local Value = Loader()
		rawset(Self, Key, Value)

		Remaining -= 1
		if Remaining == 0 then
			table.freeze(Self)
		end

		return Value
	end

	setmetatable(Members, {
		__index = function(Self, Key)
			return Load(Self, Key)
		end,

		__newindex = function(_, Key)
			error(`{Name} is read-only, cannot set {tostring(Key)}`, 2)
		end,

		__iter = function(Self)
			for Key in Loaders do
				if rawget(Self, Key) == nil then
					Load(Self, Key)
				end
			end

			return next, Self
		end,
	})

	GROUPS[Members] = true

	return Members
end

function Lazy.IsGroup(Value: any): boolean
	return GROUPS[Value] == true
end

function Lazy.LoadAll(Group: any)
	for _, Value in Group do
		if GROUPS[Value] then
			Lazy.LoadAll(Value)
		end
	end
end

return Lazy
