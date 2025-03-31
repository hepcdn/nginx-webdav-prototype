local gossip = require("gossip")

-- Handle posted message
if ngx.var.request_method == "POST" then
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if data then
        gossip.handle_message(data)
    end
end

-- Prepare gossip message
local message = gossip.prepare_message()

-- Send the message
ngx.status = ngx.HTTP_OK
ngx.header["Content-Type"] = "application/json"
ngx.header["Content-Length"] = #message
ngx.header["Cache-Control"] = "no-cache"
ngx.print(message)

return ngx.exit(ngx.OK)
