#!/usr/bin/env python3
import os
import re
import sys

proto_fields = []
class Method:
	def __init__(self, name):
		result = re.match("# \\(([0-9]+)\\) ([A-Za-z0-9_]+)", name)
		self.id = int(result[1])
		self.name = result[2]
		self.request = []
		self.response = []

def extract_name(link):
	return re.match("\\[([A-Za-z0-9 _]+)\\]\\(([A-Za-z0-9#-_]+)\\)", link)[1]

def delink(link):
	return re.sub("\\[([A-Za-z0-9 _]+)\\](?:\\([A-Za-z0-9#-_]+\\))?", lambda a: a[1], link)

def fix_html(s):
	return s.replace("&gt;", ">").replace("&lt;", "<")


struct_funcs = {}
def reg_struct(struct_name, struct_info):
	proto_fields.append((struct_name, struct_name, 'bytes', struct_name)) 
	#types[struct_name] = lambda field_name, arg_name, struct_name=struct_name, struct_info=struct_info: do_struct(field_name, arg_name, struct_name, struct_info)
	types[struct_name] = lambda field_name, arg_name, struct_name=struct_name: f"off = do_{struct_name}(tree, tvb, off, '{field_name}')"

	struct_length = 0
	func = f"function do_{struct_name}(tree, tvb, off, field_name)\n"

	func += f"""local {struct_name}_container = tree:add(F.{struct_name}, tvb(off, {struct_length}))
	{struct_name}_container:set_text("{struct_name}")
	"""

	for f in struct_info:
		func += dispatch_type(struct_name + "_" + f[0], f[0], f[1]).replace("tree", f"{struct_name}_container")

	func += "\nreturn off\nend"

	struct_funcs[struct_name] = func

types = {}
type_funcs = {}
def reg_type(type_name, func):
	type_funcs[type_name] = f"function do_{type_name}(tree, tvb, off, field_name)\n" + func(type_name, type_name) + "\nend"
	def type_thunk(field_name, arg_name, type_name=type_name, func=func, extract=False):
		func(field_name, arg_name) # TODO: why?????
		return f"off, {field_name} = do_{type_name}(tree, tvb, off, '{field_name}')"
	types[type_name] = type_thunk

def u(l, field_name, arg_name):
	proto_fields.append((field_name, arg_name, "uint{}".format(l), "uint{}".format(l)))
	func = f"tree:add_le(F[field_name], tvb(off,{l//8}))"
	if l != 64:
		func += f"return off + {l//8}, tvb(off,{l//8}):le_uint()"
	else:
		func += f"return off + {l//8}"
	return func

def i32(field_name, arg_name):
	proto_fields.append((field_name, arg_name, 'int32', 'int32'))
	return f"""tree:add_le(F[field_name], tvb(off,4))
	return off + 4, tvb(off,4):le_int()"""

reg_type('Int32', i32)
reg_type('byte', lambda a,b: u(8, a, b))
reg_type('Uint8', lambda a,b: u(8, a, b))
reg_type('Uint16', lambda a,b: u(16, a, b))
reg_type('Uint32', lambda a,b: u(32, a, b))
reg_type('Uint64', lambda a,b: u(64, a, b))

reg_type('PID', lambda a,b: u(32, a, b))
reg_type('DateTime', lambda a,b: u(64, a, b))

def buffer(l, field_name, arg_name):
	proto_fields.append((field_name+"_len", arg_name + " length", "uint{}".format(l), "Buffer"))
	proto_fields.append((field_name+"_data", arg_name + " data", "bytes", "Buffer"))

	return f"""local {field_name}_len = tvb(off,{l//8}):le_uint()
	tree:add_le(F[field_name.."_len"], tvb(off, {l//8}))
	if {field_name}_len ~= 0 then
		tree:add(F[field_name.."_data"], tvb(off+{l//8}, {field_name}_len))
		return off + {l//8} + {field_name}_len, tvb(off+{l//8}, {field_name}_len)
	else
		return off + {l//8}
	end
	"""

reg_type('Buffer', lambda a,b: buffer(32, a, b))
reg_type('qBuffer', lambda a,b: buffer(16, a, b))

def do_string(field_name, arg_name):
	proto_fields.append((field_name+"_len", arg_name + " length", "uint16", "String"))
	proto_fields.append((field_name+"_data", arg_name + " data", "string", "String"))

	return f"""local {field_name}_len = tvb(off,2):le_uint()
	tree:add_le(F[field_name.. "_len"], tvb(off, 2))
	tree:add(F[field_name.. "_data"], tvb(off+2, {field_name}_len))
	return off + 2 + {field_name}_len, tvb(off+2, {field_name}_len-1):string()"""

reg_type('String', do_string)
reg_type('StationURL', do_string)

def do_bool(field_name, arg_name):
	proto_fields.append((field_name, arg_name, "bool", "bool"))
	return f"""tree:add(F[field_name], tvb(off,1))
	return off + 1, (tvb(off,1)~= 0)"""
reg_type('Bool', do_bool)

def do_list(field_name, arg_name, list_type):
	proto_fields.append((field_name+"_len", arg_name + " length", "uint32", "uint32"))
	return f"""-- list !! {list_type}
	local {field_name}_len = tvb(off, 4):le_uint()
	subtree = tree:add_le(F.{field_name}_len, tvb(off,4))
	off = off + 4
	for i=1,{field_name}_len do
	""" + dispatch_type(field_name+"_item", arg_name, list_type).replace("tree", "subtree") + """
	end
	"""

def do_data(field_name, arg_name, full_type):
	func = ""
	func += f"""
		local {field_name}_container = tree:add(F.Data, tvb(off, 0))
		{field_name}_container:set_text("{full_type}")
	"""

	proto_fields.append((field_name+"_data_bytes", arg_name + " data bytes", "bytes", "bytes"))

	func += dispatch_type(field_name + "_type_name", arg_name + "_type_name", "String").replace("tree", f"{field_name}_container") + "\n"
	func += dispatch_type(field_name + "_len_plus_four", arg_name + "_len_plus_four", "Uint32").replace("tree", f"{field_name}_container") + "\n"
	func += dispatch_type(field_name + "_data_len", arg_name + "_data_len", "Uint32").replace("tree", f"{field_name}_container") + "\n"
	func += f"""local type_func = 'do_'..{field_name}_type_name
		if _G[type_func] ~= nil then
			off = _G[type_func]({field_name}_container, tvb, off, "{field_name}_data")
		else
			{field_name}_container:add(F.{field_name}_data_bytes, tvb(off, {field_name}_len))
			off = off + {field_name}_data_len
		end
	"""
	return func

def dispatch_type(field_unique_name, arg_name, arg_type):
	if arg_type.startswith("List"):
		list_type = arg_type[5:-1]
		if not list_type in types:
			if list_type.startswith("Data"):
				data_type = list_type[5:-1]
				if not data_type in types:
					print("Stubbed type {} in list... in data".format(data_type))
					return "--[[ Stubbed! Missing type (in list/in Data) {}]]\n".format(data_type)
			else:
				# bail.
				print("Stubbed type {} in list".format(list_type))
				return "--[[ Stubbed! Missing type (in list) {}]]\n".format(list_type)
		return do_list(field_unique_name, arg_name, list_type) + "\n"
	elif arg_type.startswith("Data"):
		if len(arg_type) > 4:
			data_type = arg_type[5:-1]
			if not data_type in types:
				print("Stubbed type {} in Data".format(data_type))
				return "--[[ Stubbed! Missing type (in Data) {}]]\n".format(data_type)
		return do_data(field_unique_name, arg_name, arg_type) + "\n"
	else:
		if not arg_type in types:
			# bail.
			print("Stubbed type {}".format(arg_type))
			return "--[[ Stubbed! Missing type {}]]\n".format(arg_type)
		else:
			return types[arg_type](field_unique_name, arg_name) + "\n"

Data_info = (
	('type_name', 'String'),
	('len_plus_four', 'Uint32'),
	('data', 'Buffer')
)
reg_struct('Data', Data_info)

RVConnectionData_info = (
	('m_urlRegularProtocols', 'StationURL'),
	('m_lstSpecialProtocols', 'List<byte>'),
	('m_urlSpecialProtocols', 'StationURL')
)
reg_struct('RVConnectionData', RVConnectionData_info)

GameKey_info = (
	('title_id', 'Uint64'),
	('title_version', 'Uint16')
)
reg_struct('GameKey', GameKey_info)

FriendPersistentInfo_info = (
	('pid', 'Uint32'),
	('unk_2', 'Uint8'),
	('unk_3', 'Uint8'),
	('unk_4', 'Uint8'),
	('unk_5', 'Uint8'),
	('unk_6', 'Uint8'),
	('favourite_game', 'GameKey'),
	('status', 'String'),
	('unk_8',  'DateTime'),
	('unk_9',  'DateTime'),
	('unk_10', 'DateTime')
)
reg_struct('FriendPersistentInfo', FriendPersistentInfo_info)

FriendPicture_info = (
	("unk", "Uint32"),
	("data", "Buffer"),
	("datetime", "DateTime")
)
reg_struct('FriendPicture', FriendPicture_info)

FriendRelationship_info = (
	('pid', 'Uint32'),
	('unk_2', 'Uint64'),
	('unk_3', 'Uint8')
)
reg_struct('FriendRelationship', FriendRelationship_info)

MyProfile_info = (
	('unk_1', 'Uint8'),
	('unk_2', 'Uint8'),
	('unk_3', 'Uint8'),
	('unk_4', 'Uint8'),
	('unk_5', 'Uint8'),
	('unk_6', 'Uint64'),
	('unk_7', 'String'),
	('unk_8', 'String')
)
reg_struct('MyProfile', MyProfile_info)

PlayedGame_info = (
	('game_key', 'GameKey'),
	('date_time', 'DateTime')
)
reg_struct('PlayedGame', PlayedGame_info)

NintendoPresence_info = (
	('m_changedBitFlag', 'Uint32'),
	('m_gameKey', 'GameKey'),
	('m_gameModeDescription', 'String'),
	('m_joinAvailabilityFlag', 'Uint32'),
	('m_matchmakeSystemType', 'Uint8'),
	('m_joinGameID', 'Uint32'),
	('m_joinGameMode', 'Uint32'),
	('m_ownerPrincipalID', 'PID'),
	('m_joinGroupID', 'Uint32'),
	('m_applicationArg', 'Buffer')
)
reg_struct('NintendoPresence', NintendoPresence_info)

FriendPresence_info = (
	('unk', 'Uint32'),
	('nintendo', 'NintendoPresence')
)
reg_struct('FriendPresence', FriendPresence_info)

Mii_info = (
	('unk_1', 'String'),
	('unk_2', 'Bool'),
	('unk_3', 'Uint8'),
	('mii_data', 'Buffer')
)
reg_struct('Mii', Mii_info)


MiiList_info = (
	('unk_1', 'String'),
	('unk_2', 'Bool'),
	('unk_3', 'Uint8'),
	('mii_data_list', 'List<Buffer>')
)
reg_struct('MiiList', MiiList_info)

Gathering_info = (
	('m_idMyself', 'Int32'),
	('m_pidOwner', 'PID'),
	('m_pidHost', 'PID'),
	('m_uiMinParticipants', 'Uint16'),
	('m_uiMaxParticipants', 'Uint16'),
	('m_uiParticipationPolicy', 'Uint32'),
	('m_uiPolicyArgument', 'Uint32'),
	('m_uiFlags', 'Uint32'),
	('m_uiState', 'Uint32'),
	('m_strDescription', 'String')
)
reg_struct('Gathering', Gathering_info)

MatchmakeSession_info = (
	('m_Gathering_base', 'Gathering'),
	('m_GameMode', 'Uint32'),
	('m_Attribs', 'List<Uint32>'),
	('m_OpenParticipation', 'Bool'),
	('m_MatchmakeSystemType', 'Uint32'),
	('m_ApplicationBuffer', 'Buffer'),
	('m_ParticipationCount', 'Uint32'),
#	('m_ProgressScore', 'Uint8'), # Added in NEX 3.5.0
#	('m_SessionKey', 'Buffer'),
#	('m_Option0', 'Uint32')
)
reg_struct('MatchmakeSession', MatchmakeSession_info)

GatheringStats_info = (
	('m_pidParticipant', 'Uint32'),
	('m_uiFlags', 'Uint32'),
	('m_lstValues', 'List<Float>')
)
reg_struct('GatheringStats', GatheringStats_info)

Invitation_info = (
	('m_idGathering', 'Uint32'),
	('m_idGuest', 'Uint32'),
	('m_strMessage', 'String')
)
reg_struct('Invitation', Invitation_info)

ParticipantDetails_info = (
	('m_idParticipant', 'Uint32'),
	('m_strName', 'String'),
	('m_strMessage', 'String'),
	('m_uiParticipants', 'Uint16')
)
reg_struct('ParticipantDetails', ParticipantDetails_info)

DeletionEntry_info = (
	('m_idGathering', 'Uint32'),
	('m_pid', 'PID'),
	('m_uiReason', 'Uint32')
)
reg_struct('DeletionEntry', DeletionEntry_info)

def lua_build_method(method_prefix, info):
	func = """function (tree, tvb)
	local off = 0
"""
	for i in info:
		arg_type = fix_html(delink(i[0]))
		arg_name = i[1]
		if arg_name == "%retval%":
			arg_name = "retval"

		field_unique_name = method_prefix + "_" + arg_name.replace(" ", "_")

		arg_detail = None
		if len(i) > 2:
			arg_detail = i[2]
		#print(method_prefix, arg_type, arg_name, '"' + str(arg_detail) + '"')
		func += dispatch_type(field_unique_name, arg_name, arg_type)
		
	func += " end"
	return func

def lua_build_proto(header, cmds, method_infos):
	result = re.match("([A-Za-z0-9 ]+) \\(([0-9A-Fa-fx?]+)\\)", header)
	proto_name = result[1]
	proto_name_safe = proto_name.replace(' ', '_')
	proto_id = result[2]
	if proto_id == '0x??':
		return ""

	cmd_list = ""
	for c in cmds:
		if c[0].startswith("0x"):
			cmd_id = int(c[0], 16)
		else:
			cmd_id = int(c[0])
		name = c[1]
		if name.startswith("["):
			name = extract_name(name)

		req = "nil"
		resp = "nil"

		if cmd_id in method_infos:
			meth_info = method_infos[cmd_id]
			req = lua_build_method(proto_name_safe + "_" + meth_info.name, meth_info.request)
			resp = lua_build_method(proto_name_safe + "_" + meth_info.name, meth_info.response)

		cmd_list += """[{}] = {{
				["name"] = "{}",
				["request"] = {},
				["response"] = {}
			}},
			""".format(cmd_id, name, req, resp)

	return """[{}] =
	{{
		["name"] = "{}",
		["methods"] = {{
{}
		}}
	}},""".format(proto_id, proto_name, cmd_list)

if not os.path.exists("NintendoClients.wiki"):
	print("Please run 'git clone https://github.com/Kinnay/NintendoClients.wiki.git'")
	exit()

if len(sys.argv) == 1:
	print("Usage: {} [output file]".format(sys.argv[0]))
	exit()

proto_info = ""

a = os.listdir("NintendoClients.wiki")
for name in a:
	if name == 'RMC-Protocol.md' or name == 'PRUDP-Protocol.md':
		continue
	if re.search("Protocol(?:-[^.]+)?.md", name):
		with open("NintendoClients.wiki/"+name) as f:
			header = f.readline().strip()
			if header.startswith("## "):
				header = header[3:]
			if header.startswith("[["): # parse link
				end = header.find("]] > ")
				if end == None:
					print("?", name)
					break
				header = header[end+5:]
				#print(header)

				# states
				CmdList = 0
				SearchingForMethod = 1
				MethodRequest = 2
				MethodResponse = 3

				cmd_list = []
				method_infos = None
				current_method = None

				state = CmdList
				table = False
				cmd = False

				skip_table = False

				for l in f.readlines():
					l=l.strip()
					if not table and l.startswith('|'):
						table = True
						continue # Skip the table header..

					if table:
						if l == '':
							if not skip_table: # Don't do state transitions if we skip a table!
								if state == CmdList:
									state = SearchingForMethod
								elif state == MethodRequest:
									state = MethodResponse
								elif state == MethodResponse:
									state = SearchingForMethod
									method_infos[current_method.id] = current_method
							table = False
						else:
							row = list(map(lambda a: a.strip(), l[1:-1].split('|')))
							if set(row) == set(['---']):
								continue

							if skip_table:
								continue

							if state == 0: # the cmd list is the first table
								cmd_list.append(row)
								method_infos = {}
							elif state == MethodRequest:
								current_method.request.append(row)
							elif state == MethodResponse:
								current_method.response.append(row)
								#exit()
					else:
						if l.startswith("# "):
							if state == SearchingForMethod:
								if l == '# Types': # lol
									continue

								current_method = Method(l)
								state = MethodRequest
							elif state == MethodResponse:
								# Maybe the method before is just missing info. That's fine.
								method_infos[current_method.id] = current_method

								current_method = Method(l)
								state = MethodRequest

						elif l.startswith("##"):
							if (state == MethodRequest and l != '## Request') or (state == MethodResponse and l != '## Response'):
								#print("Odd!", state, l)
								#print((state == MethodRequest and l != '## Request'), (state == MethodResponse and l != '## Response'))
								skip_table = True
							else:
								skip_table = False
						elif l.startswith('This method does not take any request data') or l.startswith('This method does not take any parameters'):
							state = MethodResponse
						elif l.startswith('This method does not return anything') or l.startswith("This method doesn't return anything"):
							state = SearchingForMethod
							method_infos[current_method.id] = current_method
						elif l.startswith("This method takes no parameters and doesn't return anything."):
							state = SearchingForMethod
							method_infos[current_method.id] = current_method
				if table:
					table = False

				proto_info += lua_build_proto(header, cmd_list, method_infos)+"\n"


out_file = open(sys.argv[1], 'w')
out_file.write("""-- This file is autogenerated
-- Pls dont
""")

for field in proto_fields:
	field_name, human_name, arg_type, real_type = field
	out_file.write(f"F.{field_name} = ProtoField.{arg_type}(\"{field_name}\", \"{human_name} ({real_type})\")\n")

for type_name in type_funcs:
	out_file.write(type_funcs[type_name] + "\n")

for struct_name in struct_funcs:
	out_file.write(struct_funcs[struct_name] + "\n")

out_file.write("local info = {\n")
out_file.write(proto_info)
out_file.write("}\nreturn info")
out_file.close()