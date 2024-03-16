-- example script that demonstrates response handling and
-- retrieving an authentication token to set on all future
-- requests
--

function getClientBody()
    math.randomseed(os.time())
    r = math.random(1, 3)
    -- print("Random number: " .. r)
    if r == 1 then
        return "client_id=knox&client_secret=0e645988f08d9a4c40172eb2eab9010c&grant_type=client_credentials"
    elseif r == 2 then
        return "client_id=mobileapp&client_secret=d945006f79d011712f5f72dd31e97987&grant_type=client_credentials"
    else
        return "client_id=webapp&client_secret=secret&grant_type=client_credentials"
    end
end

request = function()
    wrk.method = "POST"
    wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
    body = getClientBody()
    -- print("Body: " .. body)
    wrk.body = body
    return wrk.format(nil, "/oauth2/authorize")
end
