local ngx = require("ngx")
local openidc = require("resty.openidc")
local config = require("config")

if not ngx.var.http_authorization then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["WWW-Authenticate"] = 'Bearer realm=storage'
    ngx.say("no authorization header provided")
    return ngx.exit(ngx.OK)
end

local opts = {
    public_key = config.data.openidc_pubkey,
    token_signing_alg_values_expected = { "RS256" }
}
-- call bearer_jwt_verify for OAuth 2.0 JWT validation
local res, err = openidc.bearer_jwt_verify(opts)

if err or not res then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say(err and err or "no access token provided")
    return ngx.exit(ngx.OK)
end

if string.find(res.scope, "hepcdn.access") == nil then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say("no permission to read this resource")
    return ngx.exit(ngx.OK)
end
