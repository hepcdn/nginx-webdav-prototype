local http = require("resty.http")
local config = require("config")
local fileutil = require("fileutil")

---@type function
---@param source_uri string
---@param destination_localpath string
---@param redirects integer?
---@return nil
local function third_party_pull(source_uri, destination_localpath, redirects)
    local httpc = http.new()
    httpc:set_timeouts(config.data.tpc_connect_timeout, config.data.tpc_send_timeout, config.data.tpc_read_timeout)

    -- RequireChecksumVerification is by default true
    -- when false we don't error when the remote server fails to provide
    -- an RFC 3230 compliant checksum in the response headers
    local verify_checksum = true
    if ngx.var.http_requirechecksumverification == "false" then
        verify_checksum = false
    end

    -- SciTag is an optional header that can be used to label the traffic
    -- for monitoring purposes, either via a UDP "firefly" packet or a IPv6 flow label
    -- TODO: implement these
    if ngx.var.http_scitag then
        local scitag = tonumber(ngx.var.http_scitag)
    end

    -- At this point we have accepted the request and will report
    -- errors according to the text/perf-marker-stream format
    ngx.status = ngx.HTTP_ACCEPTED
    ngx.header["Content-Type"] = "text/perf-marker-stream"

    -- First establish a connection
    local parsed_uri, err = httpc:parse_uri(source_uri)
    if not parsed_uri then
        ngx.say("failure: failed to parse URI: " .. err)
        return ngx.exit(ngx.OK)
    end
    local scheme, host, port, path = table.unpack(parsed_uri)
    local ok, err, ssl_session = httpc:connect({
        scheme = scheme,
        host = host,
        port = port,
        ssl_verify = true,
    })
    if not ok then
        ngx.say("failure: connection to " .. host .. ":" .. port .. " failed: " .. err)
        return ngx.exit(ngx.OK)
    end

    local headers = {
        ["Host"] = host,
        ["User-Agent"] = "nginx-webdav-prototype/0.0.1", -- TODO: version from config
    }
    if verify_checksum then
        headers["Want-Digest"] = "adler32"
    end
    if ngx.var.http_transferheaderauthorization then
        headers["Authorization"] = ngx.var.http_transferheaderauthorization
    end
    local res = nil
    res, err = httpc:request({
        path = path,
        headers = headers,
    })
    if not res then
        ngx.say("failure: request to " .. host .. ":" .. port .. " for path " .. path .. " failed: " .. err)
        return ngx.exit(ngx.OK)
    end

    local is_redirect = res.status == 301 or res.status == 302 or res.status == 303 or res.status == 307 or res.status == 308
    redirects = redirects or 0
    if is_redirect and redirects < config.data.tpc_redirect_limit then
        return third_party_pull(res.headers["Location"], destination_localpath, redirects + 1)
    end

    if res.status ~= 200 then
        ngx.status = res.status
        ngx.say("failure: rejected GET: ", res.reason)
        return ngx.exit(res.status)
    end

    local adler32 = nil
    err, adler32 = fileutil.sink_to_file(destination_localpath, res.body_reader, true)

    if not adler32 then
        ngx.say("failure: error while receiving data: ", err)
        return ngx.exit(ngx.OK)
    end

    if verify_checksum then
        local source_adler32 = (res.headers["Digest"] or "adler32=(missing)"):sub(9)
        if source_adler32 ~= adler32 then
            ngx.say("failure: adler32 checksum mismatch: source ", source_adler32, " desination ", adler32)
            return ngx.exit(ngx.OK)
        end
    end

    ngx.say("success: Created")

    -- this allows the connection to be reused by other requests
    ok, err = httpc:set_keepalive()
    if not ok then
        ngx.log(ngx.ERR, "failed to set keepalive on remote connection: ", err)
        return ngx.exit(ngx.OK)
    end
end


if ngx.var.request_method == "COPY" then
    -- The COPY method is supported by ngx_http_dav_module but only for files on the same server.
    -- We intercept the method here to support third-party push copy.
    if not ngx.var.http_source then
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say("no source provided")
        return ngx.exit(ngx.OK)
    end

    if ngx.var.http_destination then
        ngx.status = ngx.HTTP_NOT_ALLOWED
        ngx.say("third-party push copy not implemented")
        return ngx.exit(ngx.OK)
    end

    third_party_pull(ngx.var.http_source, fileutil.get_request_local_path())
end