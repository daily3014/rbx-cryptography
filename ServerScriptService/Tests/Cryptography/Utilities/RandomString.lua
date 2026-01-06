-- @ScriptType: ModuleScript
--[=[
	Cryptography library: Random String Generator
	
	⚠️WARNING: This is not using cryptographically secure random numbers. 
	For Security use CSPRNG.⚠️
	
	Return type: string
	Example Usage:
		local String = RandomString(500)
--]=]

--!strict
--!optimize 2
--!native

local RandomString = function(Length: number, AsBuffer: boolean?): (string | buffer)
	local Characters = buffer.create(Length)
	
	for Index = 0, Length - 1 do
		buffer.writeu8(Characters, Index, math.random(36, 122))
	end

	return if AsBuffer
		then Characters
		else buffer.tostring(Characters)
end ::
& ( (Length: number, AsBuffer: true) -> (buffer) )
& ( (Length: number, AsBuffer: false) -> (string) )
-- overload selection for boolean/nil unions (optional types) broke a bit ago,
-- create a dedicated overload for nil to fix this issue.
& ( (Length: number, AsBuffer: nil) -> (string) )
-- fixes "None of the overloads for function that accept 2 arguments are compatible."
& ( (Length: number, AsBuffer: boolean?) -> (string | buffer) )

return RandomString