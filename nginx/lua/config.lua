local ngx = require("ngx")

local Config = {
    data = {
        -- Make sure thee are consitent with default.conf
        local_path = "/var/www/webdav",
        uriprefix = "/webdav",

        -- This is used in webdav_write_content and webdav_tpc_content
        receive_buffer_size = 1024*1024,
        -- How often to send a performance marker (in seconds)
        performance_marker_timeout = 5,

        -- This is used in webdav_tpc_content
        tpc_redirect_limit = 5,

        -- This is used in cksumutil
        checksum_block_size = 64*1024*1024,

        -- discovery = "https://cms-auth.web.cern.ch/.well-known/openid-configuration",
        -- this is the public key from the above provider
        -- it can be overridden by the config json if desired
        openidc_pubkey = [[-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnAO8vabKkITjjDht2dL+
GCB+zakuHsbwC6xaQWZpVePm3t9o0RO5r+fjgqux5iCPJSTr26QDvpdQ6aGmVWPz
W7oGKyEYCGwMxK8o69jIfDBkeXPQdWYAu5lWmoY3tm322o65s5luMKEexEwbzgj8
lFHxGGVK6xj3Vb0ky/bJPNOa2lV3SziD1PuiqoTUbkcI8+pUXMqhkvvVhtLjmhOW
nYRpXnJvRswePD3s0nSYwAWr7TyRm5r/UCr5MoZpWSUg3eBKw5YFiWY8EIBu70Ys
I0VY97z1mRO4S1TXwUwzr3NlB3JPmnJUKGRlh6ZceKnqGQWieS87rOn1aEUWNcxa
LwIDAQAB
-----END PUBLIC KEY-----]],
       -- To be able to confirm that the test server is the same one we spoke
       -- to, have the health check reply this ID. So the test sets the ID and
       -- the service replies with the same number
       health_check_id = -1,
    }
}

 function Config.load(path)
    -- Update the Config object with the values from the file at the given path
    local cjson = require("cjson")

    local f = io.open(path, "r")
    if f == nil then
       return nil
    end
    local content = f:read("*a")
    f:close()
    local newvalues = cjson.decode(content)
    for k,v in pairs(Config.data) do
        if newvalues[k] ~= nil then
            Config.data[k] = newvalues[k]
        end
    end
 end

 return Config
