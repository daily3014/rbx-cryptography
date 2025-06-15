local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Cryptography = ReplicatedStorage:WaitForChild("Cryptography")
local Tests = Cryptography.Testing

for _, Test: ModuleScript in Tests:GetChildren() do
	require(Test)
end

return nil
