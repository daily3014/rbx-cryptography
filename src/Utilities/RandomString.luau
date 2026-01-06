--[=[
	Cryptography library: Random String Generator
	
	⚠️WARNING: This is not using cryptographically secure random numbers. 
	For Security use CSPRNG.⚠️
	
	Return type: string | buffer
	Example Usage:
		local String = RandomString(500)
--]=]

--!strict
--!optimize 2
--!native

local function RandomString(Length: number, AsBuffer: boolean?): string | buffer
	local Characters = buffer.create(Length)

	for Index = 0, Length - 1 do
		buffer.writeu8(Characters, Index, math.random(36, 122))
	end

	return if AsBuffer
		then Characters
		else buffer.tostring(Characters)
end

return RandomString