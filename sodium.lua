--[[
  #!/usr/bin/lua

  local lua = require('sodium')

  print("test:", lua.test())
]]

local sodium = require("sodium.core")

local M = {
  test = sodium.test
}

return M
