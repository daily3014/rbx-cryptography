--!strict
-- Thanks @Sythivo :)

type BasicCases = {
	ToBe: (Expected: any) -> (),
	ToBeDefined: () -> (),
	ToBeCloseTo: (Expected: number, Precision: number) -> (),
	ToBeGreaterThan: (Expected: number) -> (),
	ToBeGreaterThanOrEqual: (Expected: number) -> (),
	ToBeLessThan: (Expected: number) -> (),
	ToBeLessThanOrEqual: (Expected: number) -> (),
	ToBeNil: () -> (),
	ToBeNan: () -> (),
	ToHaveLength: (Expected: number) -> (),
	ToBeFalsy: () -> (),
	ToBeTruthy: () -> (),
}

type ExpectCases = BasicCases & {
	Never: BasicCases,
}

type FunctionalCases = ExpectCases & {
	ToThrow: (Expected: string?) -> (),
	Never: FunctionalCases,
}

type ExpectHandler = {
	Any: (Type: string) -> any,
	Type: (
		Type: "nil"
			| "boolean"
			| "number"
			| "string"
			| "function"
			| "table"
			| "userdata"
			| "thread"
			| "buffer"
			| "vector"
	) -> any,
	Similar: (Expected: { [any]: any }) -> any,
}

type TestingLib = {
	Running: boolean,
	Failed: number,
	Count: number,
	Entry: (Callback: () -> ()) -> (),
	Complete: () -> (),
	Test: (Name: string, Callback: () -> ()) -> (),
	Describe: (Name: string, Callback: () -> ()) -> (),
	Defer: (Function: () -> ()) -> (),
	Expect: ((Value: (...any) -> ...any) -> FunctionalCases) & ((Value: any) -> ExpectCases) & ExpectHandler,
	Expected: (Value: any) -> (),
	ExpectEqual: (Expected: any, Value: any) -> (),
}

type TestInfo = {
	Name: string?,
}

type StackTraceInfo = {
	Source: string,
	Name: string,
	Line: number,
	Address: string,
}

local Testing = {}

Testing.Running = true

Testing.Failed = 0
Testing.Count = 0
Testing.Start = nil :: number?

local DeferQueue = {} :: { () -> () }
local ScopeStack = {} :: { string }
local TestStack = {} :: { string }

local function NonEmptyString(Value: any?): boolean
	return type(Value) == "string" and #Value > 1
end

local function WriteStackTrace(Source: string, Name: string, Line: number, Address: string): StackTraceInfo
	return {
		Source = Source,
		Name = Name,
		Line = Line,
		Address = Address,
	}
end

local function SecondsToMicroseconds(Seconds: number): number
	return math.floor(Seconds * 1000000)
end

local function FormatTime(Microseconds: number): string
	if Microseconds >= 1000000 then
		return string.format("%.2fs", Microseconds / 1000000)
	elseif Microseconds >= 1000 then
		return string.format("%.2fms", Microseconds / 1000)
	else
		return string.format("%.0fμs", Microseconds)
	end
end

local function RunTest(Function: () -> (), Info: TestInfo)
	Testing.Count += 1
	if Testing.Count % 10 == 0 then
		task.wait()
	end

	if not Testing.Start then
		Testing.Start = os.clock()
	end

	local Ok, Error
	local StackTrace = {}
	local TimeStart = os.clock()

	Ok = xpcall(Function, function(ErrorMessage)
		local LastName = debug.info(1, "n")
		for Index = 1, 30 do
			local DebugFunction, Name, Line, Source = debug.info(Index + 1, "fnls")
			if not DebugFunction then
				break
			end

			local LineNumber = LastName
			if #StackTrace > 0 or NonEmptyString(Name) then
				LastName = Name
			end
			if Line < 0 then
				continue
			end

			table.insert(StackTrace, WriteStackTrace(Source, LineNumber :: string, Line, tostring(DebugFunction)))
		end

		Error = ErrorMessage
	end)

	local TimeLength = SecondsToMicroseconds(os.clock() - TimeStart)
	local ScopePadded = if #ScopeStack > 0 then " " else ""
	local Scope = `{ScopePadded}{table.concat(ScopeStack, "/")}`
	Scope ..= ` ({Info.Name})`

	for Index = #DeferQueue, 1, -1 do
		local Value = DeferQueue[Index]
		local Success, Result: any = pcall(Value)
		if not Success then
			print(`Deferred function failed:\n    {Result}`)
		end
	end
	table.clear(DeferQueue)

	local TestType = Ok and "PASS" or "FAIL"
	if Ok then
		print(`{TestType}{Scope} [{FormatTime(TimeLength)}]`)
	else
		Testing.Failed += 1
		warn(`{TestType}{Scope} [{FormatTime(TimeLength)}]`)
		warn(`@ error: {Error}`)

		local Size = #StackTrace
		for StackIndex, StackValue in StackTrace do
			local NameHasValue = NonEmptyString(StackValue.Name)
			if StackIndex == Size then
				warn(
					`└─ {StackValue.Source}:{StackValue.Line}: {StackValue.Address:sub(11)}{NameHasValue and ` called {StackValue.Name}` or ""}`
				)
			else
				warn(
					`├─ {StackValue.Source}:{StackValue.Line}: {StackValue.Address:sub(11)}{NameHasValue and ` called {StackValue.Name}` or ""}`
				)
			end
		end
	end
end

function Testing.Describe(Name: string, Function: (...any) -> ...any): ()
	local Line = debug.info(2, "l")
	table.insert(ScopeStack, Name)

	local Ok, Error = pcall(Function :: any)
	table.remove(ScopeStack)
	if not Ok then
		Testing.Failed += 1
		print(`{Line}: Describe("{Name}", ...):`)
		print(`   {Error}`)
	end
end

function Testing.Test(Name: string, Function: (...any) -> ...any, Timeout: number?): ()
	table.insert(TestStack, Name)
	RunTest(Function, {
		Name = Name,
		Timeout = Timeout,
	})
	table.remove(TestStack)
end

function Testing.Entry(Function: (...any) -> ...any): ()
	Testing.Count = 0
	Testing.Failed = 0

	Function()

	local Time = os.clock() - (Testing.Start or os.clock())
	local Count = Testing.Count
	local Failed = Testing.Failed
	if Failed > 0 then
		print(` Tests: {Failed} failed, {Count} total`)
	else
		print(` Tests: {Count} total`)
	end

	print(` Time:  {math.ceil(Time * 1000) / 1000} s`)
end

function Testing.Complete(): ()
	local Time = os.clock() - (Testing.Start or os.clock())
	local Count = Testing.Count
	local Failed = Testing.Failed
	if Failed > 0 then
		print(` Tests: {Failed} failed, {Count} total`)
	else
		print(` Tests: {Count} total`)
	end

	print(` Time:  {math.ceil(Time * 1000) / 1000} s`)
end

function Testing.Defer(Function: () -> ())
	table.insert(DeferQueue, Function)
end

local function AssertExpect(Flipped: boolean, Value: boolean, Format: string, ...: any)
	if Flipped then
		Value = not Value
	end

	if not Value then
		error(string.format(Format, ...), 4)
	end
end

local Conditional = {}
Conditional.__index = Conditional

function Conditional.New(Name: string, Function: (Value: any) -> (boolean, string?), Any: any?)
	return setmetatable({
		Test = Function,
		Name = Name,
		Value = Any,
	}, Conditional)
end

function Conditional.Is(Any)
	return type(Any) == "table" and getmetatable(Any) == Conditional
end

type Conditional = typeof(Conditional.New("", function(_)
	return true, ""
end))

function Conditional.__call(self: Conditional, ...)
	return self.Test(...)
end

function Conditional.__tostring(self: Conditional)
	return self.Name
end

type ConditionState = {
	Received: any,
	Flipped: boolean,
	Shared: { [string]: any },
}

local function FlipTag(Flipped: boolean)
	return if Flipped then "not " else ""
end

local ReadableControl = {
	["\n"] = "\\n",
	["\r"] = "\\r",
	["\t"] = "\\t",
	["\v"] = "\\v",
	["\f"] = "\\f",
	["\b"] = "\\b",
	["\a"] = "\\a",
	["\\"] = "\\\\",
	['"'] = '\\"',
	["%"] = string.format("\\x%02X", 37),
}

local function Readable(Value: any)
	local Type = type(Value)
	if Type == "string" then
		local SafeValue = Value:gsub(".", function(Character: string)
			local Byte = Character:byte()
			if Byte < 32 or Byte > 126 then
				if ReadableControl[Character] then
					return ReadableControl[Character]
				else
					return string.format("\\x%02X", Byte)
				end
			elseif Character == "\\" then
				return "\\\\"
			elseif ReadableControl[Character] then
				return ReadableControl[Character]
			end

			return Character
		end)

		return `"{SafeValue}"`
	elseif Type ~= "table" then
		return tostring(Value)
	else
		return tostring(Value)
	end
end

local Conditionals = {
	ToBe = function(self: ConditionState, Expected: any)
		if Conditional.Is(Expected) then
			local Condition, Any, String = Expected(self.Received)
			if String then
				AssertExpect(self.Flipped, Condition, String, FlipTag(self.Flipped))
			else
				AssertExpect(
					self.Flipped,
					Condition,
					"Expected %s to %sbe %s",
					Any or Readable(self.Received),
					FlipTag(self.Flipped),
					Readable(Expected)
				)
			end
		else
			AssertExpect(
				self.Flipped,
				self.Received == Expected,
				"Expected %s to %sbe %s",
				Readable(self.Received),
				FlipTag(self.Flipped),
				Readable(Expected)
			)
		end
	end,

	ToBeDefined = function(self: ConditionState)
		AssertExpect(
			self.Flipped,
			self.Received ~= nil,
			"Expected %s to %sbe defined",
			Readable(self.Received),
			FlipTag(self.Flipped)
		)
	end,

	ToBeCloseTo = function(self: ConditionState, Expected, Precision: number)
		AssertExpect(
			self.Flipped,
			Expected == math.huge and self.Received == math.huge
				or Expected == -math.huge and self.Received == -math.huge
				or math.abs(self.Received - Expected) < (10 ^ -Precision) / 2,
			"Expected %s to be close to %s",
			Readable(self.Received),
			Expected
		)
	end,

	ToBeGreaterThan = function(self: ConditionState, Expected)
		AssertExpect(
			self.Flipped,
			self.Received > Expected,
			"Expected %s to %sbe greater than %s",
			Readable(self.Received),
			FlipTag(self.Flipped),
			Readable(Expected)
		)
	end,

	ToBeGreaterThanOrEqual = function(self: ConditionState, Expected)
		AssertExpect(
			self.Flipped,
			self.Received >= Expected,
			"Expected %s to %sbe greater than or equal to %s",
			Readable(self.Received),
			FlipTag(self.Flipped),
			Readable(Expected)
		)
	end,

	ToBeLessThan = function(self: ConditionState, Expected)
		AssertExpect(
			self.Flipped,
			self.Received < Expected,
			"Expected %s to %sbe less than %s",
			Readable(self.Received),
			FlipTag(self.Flipped),
			Readable(Expected)
		)
	end,

	ToBeLessThanOrEqual = function(self: ConditionState, Expected)
		AssertExpect(
			self.Flipped,
			self.Received <= Expected,
			"Expected %s to %sbe less than or equal to %s",
			Readable(self.Received),
			FlipTag(self.Flipped),
			Readable(Expected)
		)
	end,

	ToBeNil = function(self: ConditionState)
		AssertExpect(
			self.Flipped,
			self.Received == nil,
			"Expected %s to %sbe Nil",
			Readable(self.Received),
			FlipTag(self.Flipped)
		)
	end,

	ToBeNan = function(self: ConditionState)
		AssertExpect(
			self.Flipped,
			self.Received ~= self.Received and type(self.Received) == "number",
			"Expected %s to %sbe NaN",
			Readable(self.Received),
			FlipTag(self.Flipped)
		)
	end,

	ToHaveLength = function(self: ConditionState, Expected)
		AssertExpect(
			self.Flipped,
			#self.Received == Expected,
			"Expected %s to %shave length %s",
			Readable(self.Received),
			FlipTag(self.Flipped),
			Readable(Expected)
		)
	end,

	ToBeFalsy = function(self: ConditionState)
		AssertExpect(
			self.Flipped,
			not self.Received,
			"Expected %s to %sbe falsy",
			Readable(self.Received),
			FlipTag(self.Flipped)
		)
	end,

	ToBeTruthy = function(self: ConditionState)
		AssertExpect(
			self.Flipped,
			self.Received,
			"Expected %s to %sbe truthy",
			Readable(self.Received),
			FlipTag(self.Flipped)
		)
	end,

	ToThrow = function(self: ConditionState, Expected: string?)
		AssertExpect(
			false,
			type(self.Received) == "function",
			"Expected %s to %sbe a function",
			Readable(self.Received),
			FlipTag(self.Flipped)
		)
		local Success, Error = pcall(self.Received)
		if Expected ~= nil then
			AssertExpect(false, type(Error) == "string", "Expected error to be a string (got %s)", Readable(Error))
			AssertExpect(
				false,
				not Success,
				"Expected %s to %sthrow an error",
				Readable(self.Received),
				FlipTag(self.Flipped)
			)
			local Stripped = Error:match(`^.+:%d+: (.+)$`)
			if Stripped then
				AssertExpect(
					self.Flipped,
					Stripped == Expected,
					"Got error %s expected to %sthrow %s",
					Readable(Stripped),
					FlipTag(self.Flipped),
					Readable(Expected)
				)
			else
				AssertExpect(
					self.Flipped,
					Error == Expected,
					"Got error %s expected to %sthrow %s",
					Readable(Error),
					FlipTag(self.Flipped),
					Readable(Expected)
				)
			end
		else
			AssertExpect(
				self.Flipped,
				not Success,
				"Expected %s to %sthrow an error",
				Readable(self.Received),
				FlipTag(self.Flipped)
			)
		end
	end,
}

Conditionals.ToEqual = Conditionals.ToBe

type ScanResult = { string }

local function DeepScan(Any: any, Second: any, State: { [any]: any }, Key: string?): ScanResult
	if Any == Second then
		return {}
	end

	if Conditional.Is(Any) then
		if Any.Name ~= "@similar" then
			local Result, _, Reason = Any(Second)
			if not Result then
				return { `{Key or ""}{if Reason then string.format(Reason, "") else "failed condition"}` }
			end
			return {}
		else
			Any = Any.Value
		end
	end

	if type(Any) ~= type(Second) then
		return { `{Key or ""}(type: {type(Any)}) ~= (type: {type(Second)})` }
	end

	if type(Any) == "table" then
		if State[Any] == Second then
			return {}
		end

		State[Any] = Second
		local Chunk = {}
		local KeysHit = {}
		for EntryKey, Value in Any do
			local Result = DeepScan(Value, Second[EntryKey], State, `[{Readable(EntryKey)}]: `)
			if #Result > 0 then
				KeysHit[EntryKey] = true
			end
			for _, Difference in Result do
				table.insert(Chunk, `    {Difference}`)
			end
		end

		for EntryKey, Value in Second do
			local Result = DeepScan(Any[EntryKey], Value, State, `[{Readable(EntryKey)}]: `)
			if KeysHit[EntryKey] then
				continue
			end
			for _, Difference in Result do
				table.insert(Chunk, `    {Difference}`)
			end
		end

		if #Chunk > 0 then
			table.insert(Chunk, 1, `{Key or ""}\{`)
			table.insert(Chunk, `\}`)
			return Chunk
		end
		return {}
	end

	return { `{Key or ""}(value: {Readable(Any)}) ~= (value: {Readable(Second)})` }
end

local Expect = setmetatable({
	Nothing = Conditional.New("nothing", function(Value)
		return Value == nil
	end),

	Any = function(TypeName: string)
		if type(TypeName) ~= "string" then
			error(`Expect.Any expected string, got {type(TypeName)}`, 2)
		end
		return Conditional.New(TypeName, function(Value)
			local Type = type(Value)
			return Type == TypeName, Type, `value is supposed to %sbe of type {TypeName}, got {Type}`
		end)
	end,

	Type = function(TypeName: string)
		if type(TypeName) ~= "string" then
			error(`Expect.Type expected string, got {type(TypeName)}`, 2)
		end
		return Conditional.New(TypeName, function(Value)
			local Type = type(Value)
			return Type == TypeName, Type, `value is supposed to %sbe of type {TypeName}, got {Type}`
		end)
	end,

	Similar = function(Table: { [any]: any })
		if type(Table) ~= "table" then
			error(`Expect.Similar expected table, got {type(Table)}`, 2)
		end
		return Conditional.New("@similar", function(Value)
			local Result = DeepScan(Table, Value, {})
			return #Result == 0, nil, `value is supposed to %sbe similar to value, got:\n{table.concat(Result, "\n")}`
		end, Table)
	end,
}, {
	__call = function(self: any, Value: any)
		local Object = {
			Never = {},
		}

		local SharedState = {}
		local NormalState = {
			Received = Value,
			Flipped = false,
			Shared = SharedState,
		}
		local NeverState = {
			Received = Value,
			Flipped = true,
			Shared = SharedState,
		}
		for Key, Function in Conditionals :: { [string]: (...any) -> () } do
			Object[Key] = function(...)
				Function(NormalState, ...)
			end
			Object.Never[Key] = function(...)
				Function(NeverState, ...)
			end
		end

		return Object
	end,
})

Testing.Expect = Expect
Testing.Expected = function(Any: any)
	if not Any then
		error("Truthy value expected", 2)
	end
end

Testing.ExpectEqual = function(Any: any, Second: any)
	if Any ~= Second then
		error(string.format("Expected %s to be equal to %s", Readable(Any), Readable(Second)), 2)
	end
end

return (Testing :: any) :: TestingLib
