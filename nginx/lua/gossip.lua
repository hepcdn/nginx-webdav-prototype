local ngx = require("ngx")
local cjson = require("cjson")
local config = require("config")

local Gossip = {
}

---@type function
---@return table<string, boolean> peers, boolean starting
---Return a list of the current peers, and a boolean
---indicating if this is the first time this worker is started
function Gossip.peers()
    local peerstr = ngx.shared.gossip_data:get("peers")
    local starting = false
    if not peerstr then
        peerstr = config.data.seed_peers
        ngx.shared.gossip_data:set("peers", peerstr)
        starting = true
    end
    local peers = {}
    ---@cast peerstr string
    for peer in string.gmatch(peerstr, "[^,]+") do
        peers[peer] = true
    end
    return peers, starting
end

---@type function
---@param peer string
---@return {epoch: integer, status: string, timestamp: integer} peerdata
function Gossip.get_peerdata(peer)
    local epoch = ngx.shared.gossip_data:get("epoch:" .. peer)
    if not epoch then
        return {epoch = -1, status = "unknown", timestamp = 0}
    end
    local status = ngx.shared.gossip_data:get("status:" .. peer)
    local timestamp = ngx.shared.gossip_data:get("timestamp:" .. peer)
    return {epoch = epoch, status = status, timestamp = timestamp}
end

---@type function
---@param peer string
---@param peerdata {epoch: integer, status: string, timestamp: integer}
function Gossip.set_peerdata(peer, peerdata)
    ngx.shared.gossip_data:set("epoch:" .. peer, peerdata.epoch)
    ngx.shared.gossip_data:set("status:" .. peer, peerdata.status)
    ngx.shared.gossip_data:set("timestamp:" .. peer, peerdata.timestamp)
end

---@type function
---@param peer string
---@param peerdata {epoch: integer, status: string, timestamp: integer}
function Gossip.update_peerdata(peer, peerdata)
    local current_timestamp = ngx.shared.gossip_data:get("timestamp:" .. peer)
    if current_timestamp and current_timestamp > peerdata.timestamp then
        return
    elseif current_timestamp == nil and peer ~= config.data.server_address then
        -- Check if we agree on http or https and if not we don't add the peer
        if peer:sub(0, 5) ~= config.data.server_address:sub(0, 5) then
            ngx.log(ngx.WARN, "Not adding new peer " .. peer .. " because it does not have the same security level as us")
            return
        end
        ngx.log(ngx.WARN, "Adding new peer " .. peer)
        -- Set its data first to reduce race conditions?
        Gossip.set_peerdata(peer, peerdata)
        -- Potential TODO: factor this out to a once-per-gossip update
        local peerstr = ngx.shared.gossip_data:get("peers")
        ---@cast peerstr string
        if peerstr:find(peer, 0, true) == nil then
            ngx.shared.gossip_data:set("peers", peerstr .. "," .. peer)
        end
    else
        Gossip.set_peerdata(peer, peerdata)
    end
end


---@type function
---@return string message
---Prepare a message to send to peers representing our current view of the network
function Gossip.prepare_message()
    local peers, _ = Gossip.peers()

    local message = {}
    for peer,_ in pairs(peers) do
        local peerdata = Gossip.get_peerdata(peer)
        table.insert(message, {
            name = peer,
            data = peerdata,
        })
    end

    -- Update our own data
    local selfdata = Gossip.get_peerdata(config.data.server_address)
    selfdata.epoch = selfdata.epoch + 1
    selfdata.status = "alive"
    selfdata.timestamp = ngx.now()
    Gossip.set_peerdata(config.data.server_address, selfdata)
    table.insert(message, {
        name = config.data.server_address,
        data = selfdata,
    })

    return cjson.encode(message)
end

---@type function
---@param message string
---Handle a message received from a peer
function Gossip.handle_message(message)
    local peerdata = cjson.decode(message)
    if type(peerdata) == "table" then
        for _, peerinfo in ipairs(peerdata) do
            -- Ignore our own data
            if peerinfo.name ~= config.data.server_address then
                Gossip.update_peerdata(peerinfo.name, peerinfo.data)
            end
        end
    end
end

return Gossip
