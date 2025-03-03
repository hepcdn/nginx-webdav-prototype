local uv = require('luv')
local ngx = require('ngx')
local ffi = require('ffi')
local http = require('resty.http')
  ffi.cdef[[
  int setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
  ssize_t getxattr(const char *path, const char *name, void *value, size_t size);
  ]]

--
-- Probably a naiive implementation of adler32, but it works
--
local function adler32_increment(state, buf)
  -- State is a = 1, b = 0 for first call
  local mod_adler = 65521
  for s in buf:gmatch"." do
    local c = string.byte(s)
    state['a'] = (state['a'] + c) % mod_adler
    state['b'] = (state['b'] + state['a']) % mod_adler
  end
  return state
end

local function adler32_finalize(state)
  return bit.bor(bit.lshift(state['b'], 16), state['b'])
end

local function setxattr(path, key, value)
  ffi.C.setxattr(path, key, value, string.len(value), 0);
end

---@type function
---@param source_uri string
---@param destination_localpath string
local function third_party_pull(source_uri, destination_localpath)
    local httpc = http.new()

    -- First establish a connection
    local scheme, host, port, path = table.unpack(httpc:parse_uri(source_uri))
    local ok, err, ssl_session = httpc:connect({
        scheme = scheme,
        host = host,
        port = port,
        ssl_verify = false, -- FIXME: disable SSL verification for testing
    })
    if not ok then
        ngx.status = ngx.HTTP_GATEWAY_TIMEOUT
        ngx.say("connection to " .. source_uri .. " failed: " .. err)
        return ngx.exit(ngx.OK)
    end

    local headers = {
        ["Host"] = host,
    }
    if ngx.var.http_transferheaderauthorization then
        headers["Authorization"] = ngx.var.http_transferheaderauthorization
    end
    local res, err = httpc:request({
        path = path,
        headers = headers,
    })
    if not res then
        ngx.status = ngx.HTTP_BAD_GATEWAY
        ngx.say("request to path" .. path .. " failed: " .. err)
        return ngx.exit(ngx.OK)
    end

    -- TODO: count redirects and stop after some limit
    if res.status == 302 then
        return third_party_pull(res.headers["Location"], destination_localpath)
    end

    if res.status ~= 200 then
        ngx.status = res.status
        ngx.say("request failed: ", res.reason)
        return ngx.exit(res.status)
    end

    -- At this point, the status and headers will be available to use in the `res`
    -- table, but the body and any trailers will still be on the wire.
    local file, err = io.open(destination_localpath, "w+b")
    if file == nil then
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say("failed to open destination file: ", err)
        return ngx.exit(ngx.OK)
    end

    -- We can use the `body_reader` iterator, to stream the body according to our desired buffer size.
    local reader = res.body_reader
    local buffer_size = 16*1024*1024
    ngx.say("Beginning TPC")
    local bytes_moved = 0
    local last_marker_time = uv.now()
    local adler_state = {a=1, b=0}
    repeat
        local buffer, err = reader(buffer_size)
        local closed = err:sub(1, 6) == "closed"
        if err and not closed then
            ngx.log(ngx.ERR, err)
            break
        end
        if buffer then
            local current_time = uv.now()
            if (current_time - last_marker_time > 1000) then
              last_marker_time = current_time
              ngx.say("TODO - add performance markers (needed for gfal) " .. current_time)
            end
            -- TODO: build checksum
            -- can use LuaJIT FFI to call C function
            -- https://stackoverflow.com/questions/53805913/how-to-define-c-functions-with-luajit
            -- e.g. a C function for https://en.wikipedia.org/wiki/Adler-32
            -- libz has this function
            -- TODO: coroutine https://www.lua.org/manual/5.1/manual.html#2.11
            adler_state = adler32_increment(adler_state, buffer) 
            file:write(buffer)
        end
        if closed then
          break
        end
    until not buffer
    ngx.say("TPC complete")
    file:close()
    local adler_value = adler32_finalize(adler_state)
    ngx.say("Adler32 is " .. adler_value)
    setxattr(destination_localpath, "user.nginx-webdav.adler32", tostring(adler_value))

    -- this allows the connection to be reused by other requests
    ok, err = httpc:set_keepalive()
    if not ok then
        -- TODO: is this a fatal error?
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say("failed to set keepalive: ", err)
        return ngx.exit(ngx.OK)
    end
end

local function getxattr(path, key, value)
  -- FIXME this doesn't work at all since we need to receive the string back
  -- from a pointer to a void*
  -- https://luajit.org/ext_ffi_tutorial.html
  return ffi.C.getxattr(path, key, value, string.len(value), 0);
end

if ngx.var.request_method == "COPY" then
    -- The COPY method is supported by ngx_http_dav_module but only for files on the same server.
    -- We intercept the method here to support third-party push copy.
    -- TODO: is this the best spot in the request lifecycle to do this?
    -- https://openresty-reference.readthedocs.io/en/latest/Directives/
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

    -- TODO: better way to find the local file location?
    third_party_pull(ngx.var.http_source, "/var/www" .. ngx.var.request_uri)

    -- At this point, the connection will either be safely back in the pool, or closed.
    return ngx.exit(ngx.HTTP_OK)
elseif ngx.var.request_method == "GET" then
  -- TODO handle range requests
  local fd = uv.fs_open("/var/www" .. ngx.var.request_uri, "r", 644)
  if not fd then
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("Could not open file")
    return ngx.exit(ngx.OK)
  end
  -- Amount we try to read from the filesystem at a time, most distributed
  -- filesystems have large "block sizes", so lets try a bigger number than
  -- usual
  local buffer_size = 64 * 1024 * 1024
  repeat
    -- TODO error handling
    local buffer = uv.fs_read(fd, buffer_size)
    ngx.print(buffer)
  until not buffer
  return ngx.exit(ngx.HTTP_OK)
elseif ngx.var.request_method == "PUT" then
  -- TODO write coalescing, we don't want to send a bunch of <1MB writes to a
  -- distributed filesystem
  -- TODO we don't support ranged writes (screws with checksum)
  local fd, err = uv.fs_open("/var/www" .. ngx.var.request_uri, "w", tonumber('644', 8))
  if not fd then
    ngx.say("PUT error " .. err)
    ngx.status = ngx.HTTP_NOT_ALLOWED
    return ngx.exit(ngx.OK)
  end
  local sock, err = ngx.req.socket()
  if not sock then
    ngx.say("PUT error " .. err)
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    return ngx.exit(ngx.OK)
  end
  -- Same justification as GET above
  local buffer_size = 64 * 1024 * 1024
  local adler_state = {a=1, b=0}
  -- TODO need to unify this with the 3rd party handler. Pass in the read fn?
  -- fns are first class citizens in lua, right?
  repeat
    -- TODO error handling
    local buffer, err = sock:receiveany(buffer_size)
    if buffer then
      adler_state = adler32_increment(adler_state, buffer) 
      uv.fs_write(fd, buffer)
    end
  until not buffer
  local adler_value = adler32_finalize(adler_state)
  ngx.say("Adler32 is " .. adler_value)
  setxattr("/var/www" .. ngx.var.request_uri, "user.nginx-webdav.adler32", tostring(adler_value))
  return ngx.exit(ngx.HTTP_OK)
else
  ngx.status = ngx.HTTP_NOT_ALLOWED
  ngx.say("The request " .. ngx.var.request_method .. " is not implemented")
  return ngx.exit(ngx.OK)
end


