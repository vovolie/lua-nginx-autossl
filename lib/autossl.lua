local cjson = require('cjson')
local http = require('resty.http')
local ssl = require('ngx.ssl')
local ocsp = require('ngx.ocsp')
local pcall = pcall
local json = require('cjson')
local ngx_sleep = ngx.sleep
local WATCH_RETRY_TIMER = 30  -- 轮询consul时间间隔，10s
local CONSUL_URL = "http://10.10.20.37:8500/v1/kv/ssl/?recurse" -- consul的服务地址
local ok, new_tab = pcall(require, "table.new")

if not ok or type(new_tab) ~= "function" then
    new_tab = function (narr, nrec) return {} end
end

local _M = new_tab(0, 5)

_M.VERSION = "0.01"
_M._cache = {}

local function _timer(...)
    local ok, err = ngx.timer.at(...)
    if not ok then
        ngx.log(ngx.ERR, "[FATAL] autossl: failed to create timer: ", err)
    end
end

local function _persist(table_name, data)
    if _M.shared_cache then
        _M.shared_cache:set(table_name, json.encode(data))
        return
    end
    _M._cache[table_name] = data
end

local function _aquire(table_name)
    if _M.shared_cache then
        local table_json = _M.shared_cache:get(table_name)
        return table_json and json.decode(table_json) or nil
    end
    return _M._cache[table_name]
end

-- 定时从consul刷取ssl 公钥和私钥，consul上的Key是以ssl/域名/crt表示证书，ssl/域名/key表示私钥
local function _refresh()
    local httpc = http.new()
    httpc:set_timeout(500)
    local res, err= httpc:request_uri(CONSUL_URL, {
        method = "GET",
        headers = {
            ["Content-Type"] = "application/json",
        }
    })

    if not res then
        ngx.log(ngx.ERR, "[FATAL] autossl: failed to execute request.")
        return false
    end

    if res.status ~= 200 then
        ngx.log(ngx.ERR, "[FATAL] autossl: failed to execute request. Consul returned: " .. status)
        return false
    end

    local data, err = json.decode(res.body)

    if not data or err ~= nil then
        ngx.log(ngx.ERR, "[FATAL] autossl: failed to covert to json. " .. err)
        return false
    end

    for i=1, #data do
        local aquire = _aquire(data[i]['Key'])
        local temp = {}
        temp['CreateIndex'] = data[i]['CreateIndex']
        temp['Flags'] = data[i]['Flags']
        temp['Key'] = data[i]['Key']
        temp['LockIndex'] = data[i]['LockIndex']
        temp['ModifyIndex'] = data[i]['ModifyIndex']
        temp['Value'] = ngx.decode_base64(data[i]['Value'])
        if aquire == nil then
            ngx.log(ngx.ERR, "[OK] autossl: successed write to cache. " .. temp['Key'])
            _persist(data[i]['Key'], temp)
        elseif aquire['ModifyIndex'] < temp['ModifyIndex'] then
            ngx.log(ngx.ERR, "[OK] autossl:  cache modify index less than consul " .. aquire['ModifyIndex'] .. '<' ..temp['ModifyIndex']..'  '.. temp['Key'])
            _persist(data[i]['Key'], temp)
        else
            ngx.log(ngx.ERR, "[OK] autossl: don't need to refresh.")
        end
    end
    httpc:close()

    return true

end

local function _watch(premature)
    if premature then
        return nil
    end
    if not _refresh() then
        ngx.log(ngx.ERR, "[FATAL] autossl: failed to refresh from consuls.")
    end
    _timer(WATCH_RETRY_TIMER, _watch)
end

local function _get_ocsp_response(fullchain)

    local fullchain_der, fullchain_der_err = ssl.cert_pem_to_der(fullchain)
    if not fullchain_der or fullchain_der_err then
        return nil, "failed to covert certificate chain from PEM to DER: " .. (fullchain_der_err or "")
    end

    local ocsp_url, ocsp_responder_err = ocsp.get_ocsp_responder_from_der_chain(fullchain_der)
    if not ocsp_url then
        return nil, "failed to get OCSP responder: " .. (ocsp_responder_err or "")
    end

    -- Generate the OCSP request body.
    local ocsp_req, ocsp_request_err = ocsp.create_ocsp_request(fullchain_der)
    if not ocsp_req then
        return nil, "failed to create OCSP request: " .. (ocsp_request_err or "")
    end

    -- Make the OCSP request against the OCSP server.
    local httpc = http.new()
    httpc:set_timeout(10000)
    local res, req_err = httpc:request_uri(ocsp_url, {
        method = "POST",
        body = ocsp_req,
        headers = {
            ["Content-Type"] = "application/ocsp-request",
        }
    })

    -- Perform various checks to ensure we have a valid OCSP response.
    if not res then
        return nil, "OCSP responder query failed (" .. (ocsp_url or "") .. "): " .. (req_err or "")
    end

    if res.status ~= 200 then
        return nil, "OCSP responder returns bad HTTP status code (" .. (ocsp_url or "") .. "): " .. (res.status or "")
    end

    local ocsp_resp = res.body
    if not ocsp_resp or ocsp_resp == "" then
        return nil, "OCSP responder returns bad response body (" .. (ocsp_url or "") .. "): " .. (ocsp_resp or "")
    end

    local ok, ocsp_validate_err = ocsp.validate_ocsp_response(ocsp_resp, fullchain_der)
    if not ok then
        return nil, "failed to validate OCSP response (" .. (ocsp_url or "") .. "): " .. (ocsp_validate_err or "")
    end

    return ocsp_resp  
end

local function _set_ocsp_stapling(domain, cert_pem)
    -- Fetch the OCSP stapling response from the cache, or make the request to 
    -- fetch it.
    local ocsp_resp, ocsp_response_err 
    ocsp_resp = _M.shared_cache:get("domain:ocsp:" .. domain)
    if ocsp_resp == nil then
        ocsp_resp, ocsp_response_err = _get_ocsp_response(cert_pem)
        
        if ocsp_response_err then
            return false, "failed to get ocsp response: " .. (ocsp_response_err or "")
        end

        -- Cache the OCSP stapling response for 1 hour (this is what nginx does by default).
        local _, set_ocsp_err, set_ocsp_forcible = _M.shared_cache:set("domain:ocsp:" .. domain, ocsp_resp, 3600)
        if set_ocsp_err then
            ngx.log(ngx.ERR, "failed to set shdict cache of OCSP response for " .. domain .. ": ", set_ocsp_err)
        elseif set_ocsp_forcible then
            ngx.log(ngx.ERR, "'lua_shared_dict sslcache' might be too small - consider increasing its configured size (old entries were removed while adding OCSP response for " .. domain .. ")")
        end
    end

    -- Set the OCSP stapling response.
    
    local ok, ocsp_status_err = ocsp.set_ocsp_status_resp(ocsp_resp)
    if not ok then
        return false, "failed to set ocsp status resp: " .. (ocsp_status_err or "")
    end

    return true
end

function _M.watch()
    if _M.shared_cache and ngx.worker.id() > 0 then
        return
    end
    _timer(0, _watch)
end

function _M.set_shared_dict_name(dict_name)
    _M.shared_cache = ngx.shared[dict_name]
    if not _M.shared_cache then
        ngx.log(ngx.ERR, "[FATAL] autossl: unabe to access shared dict: ", dict_name)
        return ngx.exit(ngx.ERROR)
    end
end

function _M.ssl_certificate()
    local ok, err = ssl.clear_certs()
    if not ok then
        ngx.log(ngx.ERR, "[FATAL] autossl: failed to clear existing certificates")
        return ngx.exit(ngx.ERROR)
    end
    local server_name = ssl.server_name()

    
    ngx.log(ngx.ERR, "server name is: ", server_name)
    if server_name ~= nil then
        server_name = ngx.re.match(server_name, [=[[a-z0-9]+\.[a-z0-9]+$]=],"jo")[0]
        local cache_crt = _aquire("ssl/".. server_name .. "/crt")
        local cache_key = _aquire("ssl/".. server_name .. "/key")
        if cache_crt == nil or cache_key == nil then
            if not _refresh() then
                ngx.log(ngx.ERR, "[FATAL] autossl: unable to refresh from consul.")
                return
            end
            cache_crt = _aquire("ssl/".. server_name .. "/crt")
            cache_key = _aquire("ssl/".. server_name .. "/key")
        end

        if cache_crt ~= nil or cache_key ~= nil then
            -- Set OCSP stapling.
            local ok, err = _set_ocsp_stapling(server_name, cache_crt['Value'])
            if not ok then
                ngx.log(ngx.ERR, "[FATAL] autossl: failed to set ocsp stapling for ", server_name, " - continuing anyway - ", err)
            end

            local cert_chain, err = ssl.parse_pem_cert(cache_crt['Value'])
            if not cert_chain then
                ngx.log(ngx.ERR, "[FATAL] autossl: failed to parse PEM cert: .", err)
                return
            end
            local ok, err = ssl.set_cert(cert_chain)
            if not ok then
                ngx.log(ngx.ERR, "[FATAL] autossl: failed to set cert: .", err)
                return
            end

            local priv_key, err = ssl.parse_pem_priv_key(cache_key['Value'])
            if not priv_key then
                ngx.log(ngx.ERR, "[FATAL] autossl: failed to parse PEM key: .", err)
                return
            end
            local ok, err = ssl.set_priv_key(priv_key)
            if not ok then
                ngx.log(ngx.ERR, "[FATAL] autossl: failed to set private key: ", err)
                return
            end
        else
            ngx.log(ngx.ERR, "[WARNING] autossl: cert not exist!")
            return ngx.exit(ngx.ERROR)
        end
    end
end


return _M