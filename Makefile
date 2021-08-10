ROCKSPEC =
LUAROCKS_API_KEY =

luarocks-pack:
	luarocks pack $(ROCKSPEC)

luarocks-upload:
	luarocks upload $(ROCKSPEC) --api-key=$(LUAROCKS_API_KEY)
