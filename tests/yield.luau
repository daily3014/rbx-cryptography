local function PCallResult<T, Args..., Ret...>(func: (Args...) -> Ret..., ...: Ret...): T
    return select(2, pcall(func, ...))    
end

type TaskLibrary = {
    wait: ((number) -> number)?
}

local Libraries: {TaskLibrary?} = {
    PCallResult(require, "@eryx/task"),
    PCallResult(require, "@std/task"),
    task
}

for _, Library in Libraries do
    if not Library then
        continue
    end

    if not Library.wait then
        continue
    end

    return Library.wait()
end

return -1