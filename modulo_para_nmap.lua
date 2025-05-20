
-- Modulo para Nmap

-- Importando as Bibliotecas
local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"

-- Descrição do Script
description = [[
    Script simples que busca arquivos sensíveis
]]

author = "XPSec Security"
license = "https://nmap.org/book/man-legal.html"
categories = {"default"}
blog = "https://xpsec.co"
portrule = shortport.service({"http","https"},"tcp","open")

-- Lista de Arquivos / Diretórios
action = function(host, port)
    out = stdnse.output_table()
    local status, result , body = http.identify_404(host,port)
    local all = nil
    request_paths = {
        "/secured/phpinfo.php",
        "/manager/html",
        "/phpmyadmin/",
        "/web-console",
        "/jmx-console",
        "/host-manager"
    }

-- Requisição dos arquivos via GET
for key, value in ipairs(request_paths)
    do
        all = http.pipeline_add(value,nil,all,'GET')
    end

    local results = http.pipeline_go(host, port, all)

-- Exibição na tela caso exista
for num, res in ipairs(result)do
        if(res.status ~= result)then
            out[num] = request_paths[num]
        end
    end

    return out
end
