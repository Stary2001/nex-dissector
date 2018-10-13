-- USER_DIR is initialized in ${GLOBAL_CONFIG_DIR}/init.lua
local basedir = ( USER_DIR or persconffile_path() )..'lua/'
package.path = package.path .. ";" .. basedir .. "?.lua" .. ";" .. basedir .. "nex/?.lua"

dofile(basedir .. "nex/prudp_v0_dissector.lua")
dofile(basedir .. "nex/prudp_v1_dissector.lua")
dofile(basedir .. "nex/nex_dissector.lua")
