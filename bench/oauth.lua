-- example script that demonstrates response handling and
-- retrieving an authentication token to set on all future
-- requests
--

function getClientBody()
    math.randomseed(os.time())
    r = math.random(1, 3)
    -- print("Random number: " .. r)
   --  if r == 1 then
   --      return "client_id=knox&client_secret=0e645988f08d9a4c40172eb2eab9010c&grant_type=client_credentials"
   --  elseif r == 2 then
   return "client_id=testclient&client_secret=gmDjNd@{9Z\"8La:j3u})4?8//&grant_type=client_credentials&scope="
   --  else
   --      return "client_id=webapp&client_secret=secret&grant_type=client_credentials"
   --  end
end

request = function()
    wrk.method = "POST"
    wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
    body = getClientBody()
    wrk.body = body
    return wrk.format(nil, "/oauth/token")
end

