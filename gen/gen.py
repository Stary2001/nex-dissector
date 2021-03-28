#!/usr/bin/env python3
import os
import re
import sys

is_proto = False
is_types = False

proto_fields = []
class Method:
	def __init__(self, name):
		result = re.match("# \\(([0-9]+)\\) ([A-Za-z0-9_]+)", name)
		if result == None:
			self.id = None
			self.name = name.replace("# ", "")
		else:
			self.id = int(result[1])
			self.name = result[2]
		self.request = []
		self.response = []

class Type:
	def __init__(self, name):
		self.fields = []
		result = re.match("###? ([^\\(]+)(?:\\((\S+)\\))?", name)
		if result == None:
			print("????")

		self.name = result[1].strip().replace(" ", "_")
		if result[2] != None:
			self.base = delink(result[2])
			self.fields.append(('Base', self.base, None))
		else:
			self.base = None

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
	types[struct_name] = lambda field_name, arg_name, struct_name=struct_name: f"off = do_{struct_name}(conn, tree, tvb, off, '{field_name}')"

	struct_length = 0
	func = f"function do_{struct_name}(conn, tree, tvb, off, field_name)\n"

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
	type_funcs[type_name] = f"function do_{type_name}(conn, tree, tvb, off, field_name)\n" + func(type_name, type_name) + "\nend"
	def type_thunk(field_name, arg_name, type_name=type_name, func=func, extract=False):
		func(field_name, arg_name) # TODO: why?????
		return f"off, {field_name} = do_{type_name}(conn, tree, tvb, off, '{field_name}')"
	types[type_name] = type_thunk

def int_field(l, field_name, arg_name, signed=False):
	if signed:
		prefix = ""
	else:
		prefix = "u"
	proto_fields.append((field_name, arg_name, f"{prefix}int{l}", f"uint{l}"))
	func = f"tree:add_le(F[field_name], tvb(off,{l//8}))"
	if l != 64:
		func += f"return off + {l//8}, tvb(off,{l//8}):le_{prefix}int()"
	else:
		func += f"return off + {l//8}"
	return func

def i32(field_name, arg_name):
	proto_fields.append((field_name, arg_name, 'int32', 'int32'))
	return f"""tree:add_le(F[field_name], tvb(off,4))

	return off + 4, tvb(off,4):le_int()"""

reg_type('Sint8', lambda a,b: int_field(8, a, b, True))
reg_type('Sint16', lambda a,b: int_field(16, a, b, True))
reg_type('Sint32', lambda a,b: int_field(32, a, b, True))
reg_type('Sint64', lambda a,b: int_field(64, a, b, True))
reg_type('Int32', lambda a,b: int_field(32, a, b, True))

reg_type('byte', lambda a,b: int_field(8, a, b))
reg_type('Uint8', lambda a,b: int_field(8, a, b))
reg_type('Uint16', lambda a,b: int_field(16, a, b))
reg_type('Uint32', lambda a,b: int_field(32, a, b))
reg_type('Uint64', lambda a,b: int_field(64, a, b))

reg_type('PID', lambda a,b: int_field(32, a, b))
reg_type('Result', lambda a,b: int_field(32, a, b))
reg_type('DateTime', lambda a,b: int_field(64, a, b))

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

def do_float(l, field_name, arg_name):
	if l == 4:
		n = "float"
	elif l == 8:
		n = "double"
	proto_fields.append((field_name, arg_name, n, n))
	return f"""tree:add_le(F[field_name], tvb(off,{l}))
	return off + {l}, tvb(off,{l}):le_float()"""
reg_type('Float', lambda a,b: do_float(4, a, b))
reg_type('Double', lambda a,b: do_float(8, a, b))

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
			off = _G[type_func](conn, {field_name}_container, tvb, off, "{field_name}_data")
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
			if list_type.startswith("Data<"):
				data_type = list_type[5:-1]
				if not data_type in types:
					print("Stubbed type {} in list... in data".format(data_type))
					return "--[[ Stubbed! Missing type (in list/in Data) {}]]\n".format(data_type)
			else:
				# bail.
				print("Stubbed type {} in list".format(list_type))
				return "--[[ Stubbed! Missing type (in list) {}]]\n".format(list_type)
		return do_list(field_unique_name, arg_name, list_type) + "\n"
	elif arg_type == 'Data' or arg_type.startswith("Data<"):
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
Structure_info = (
)
reg_struct('Structure', Structure_info)

ResultRange_info = (
	('m_uiOffset', 'Uint32'),
	('m_uiSize', 'Uint32')
)
reg_struct('ResultRange', ResultRange_info)


def lua_build_method(method_prefix, info):
	func = """function (conn, tree, tvb)
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
	result = re.search("([A-Za-z0-9 ]+) \\(([0-9A-Fa-fx?]+)\\)", header)
	print(header,result)
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

struct_infos = {}
def types_pass(f):
	global struct_infos, is_types

	# First pass: get type info
	table = False
	skip_table = not is_types
	sticky_skip_table = False

	current_type = None
	#should_parse_type = is_types # If it's a types page, all of it is types.
	# Fuck it
	should_parse_type = True
	for l in f.readlines():
		l = l.strip()
		if not table and l.startswith('|'):
			if 'This structure inherits from' in l:
				print(current_type, should_parse_type)
				base = delink(re.search("This structure inherits from ([^|]+) \|", l)[1])
				current_type.base = base # lol
				current_type.fields.append(('Base2', base, None))
				table = True
				skip_table = True
				print("We got some weird inheritance!", base)
				#exit()
				continue
			else:
				table = True
				if should_parse_type:
					fields = list(map(lambda a: a.strip(), filter(None, l.split("|"))))
					allowed_tables = [
						['Type','Name','Description'],
						['Type','Description'],
						['Type','Name']
					]
					if fields not in allowed_tables:
						#print("Got weird table ", l)
						skip_table = True
				continue # Skip the table header..
		if table:
			if l == '': # End of table
				if not skip_table and should_parse_type:
					fixed = []
					for f_name, t_name, rename_count in current_type.fields:
						if rename_count == None:
							fixed.append((f_name, t_name))
						else:
							fixed.append((f_name + str(rename_count), t_name))
					struct_infos[current_type.name] = fixed
				skip_table = sticky_skip_table
				table = False
			else:
				row = list(map(lambda a: a.strip(), l[1:-1].split('|')))
				if set(row) == set(['---']):
					continue
				if skip_table:
					continue
				if should_parse_type:
					field_name_safe = delink(row[1]).replace(' ', '_').replace("(","").replace(")","")
					type_name_safe = fix_html(delink(row[0]))

					rename_needed = False
					max_n = 0
					for i,f in enumerate(current_type.fields):
						if field_name_safe == f[0]:
							print("Field name collision!", f[0])
							rename_needed = True
							if len(f) < 3:
								max_n = 1
							else:
								if f[2] == None:
									max_n = 1
								else:
									max_n = f[2]
					if rename_needed:
						current_type.fields.append((field_name_safe, type_name_safe, max_n + 1))
					else:
						current_type.fields.append((field_name_safe, type_name_safe, None))
		else:
			if l == '# Types':
				should_parse_type = True
			elif l.startswith("## ") or l.startswith("### ") and should_parse_type:
				if sticky_skip_table:
					sticky_skip_table = False
					skip_table = False

				#print(l)
				# Hack lmao
				if l == '## Request' or l == '## Response':
					skip_table = True
					sticky_skip_table = True
				else:
					current_type = Type(l)
			

def methods_pass(f):
	global proto_info
	header = f.readline().strip()

	if "Pia Protocols" in header:
		return

	if header.startswith("## "):
		header = header[3:]
	if header.startswith("[["): # parse link
		end = header.find("]] > ")
		if end == None:
			print("?", name)
			return
		header = header[end+5:]

	# Second (more complicated) pass: get method info.
	# states
	CmdList = 0
	SearchingForMethod = 1
	MethodRequest = 2
	MethodResponse = 3

	cmd_list = []
	method_infos = None
	current_method = None

	state = CmdList
	
	cmd = False
	table = False
	skip_table = False

	for l in f.readlines():
		l = l.strip()
		if not table and l.startswith('|'):
			table = True
			continue # Skip the table header..

		if table:
			if l == '': # End of table
				if not skip_table: # Don't do state transitions if we skip a table!
					if state == CmdList:
						state = SearchingForMethod
					elif state == MethodRequest:
						state = MethodResponse
					elif state == MethodResponse:
						state = SearchingForMethod
						method_infos[current_method.id] = current_method
				table = False
			else: # Table row
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
		else:
			if l.startswith("# "):
				if state == SearchingForMethod:
					meth = Method(l)
					found = False
					for m in cmd_list:
						if delink(m[1]) == meth.name:
							found = True
					if not found:
						#print("Skipping non-method ", l)
						continue
					current_method = meth
					state = MethodRequest
				elif state == MethodResponse:
					# Maybe the method before is just missing info. That's fine.
					method_infos[current_method.id] = current_method

					current_method = Method(l)
					state = MethodRequest
			elif l.startswith("##"):
				if (state == MethodRequest and l != '## Request') or (state == MethodResponse and l != '## Response'):
					#print("Odd!", state, l)
					#	print((state == MethodRequest and l != '## Request'), (state == MethodResponse and l != '## Response'))
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

if not os.path.exists("NintendoClients.wiki"):
	print("Please run 'git clone https://github.com/Kinnay/NintendoClients.wiki.git'")
	exit()

if len(sys.argv) == 1:
	print("Usage: {} [output file]".format(sys.argv[0]))
	exit()

proto_info = ""

blacklist = [
	'RMC-Protocol.md'.lower(),
	'PRUDP-Protocol.md'.lower(),
	'PIA-Protocol.md'.lower(),
	'ENL-Protocol.md'.lower(),
	'Mario-Kart-8-Protocol.md'.lower(),
	'NEX-Common-Types.md'.lower(),
	'PIA-Types.md'.lower(),
	'LAN-Protocol.md'.lower(),
	'Eagle-Protocol.md'.lower(),
	'Station-Protocol.md'.lower(),
	'Web-Notification-Storage-Protocol.md'.lower(),
	'User-Storage-Admin-Protocol.md'.lower()
]

a = os.listdir("NintendoClients.wiki")
for name in a:
	if name.lower() in blacklist:
		continue
	is_proto =  re.search("Protocol(?:-[^.]+)?.md", name)
	is_types = re.search("Types(?:-[^.]+)?.md", name)

	if is_proto or is_types:
		with open("NintendoClients.wiki/"+name) as f:
			print(name)
			header = f.readline().strip()
			if "Pia Protocols" in header:
				continue
			types_pass(f)

print("=====================================================================")

prereq_types = []

def pull_prereqs(l):
	top = []
	for item in l[:]: # Copy the list!
		for f_name, f_type in struct_infos[item]:
			if f_type.startswith("List"):
				f_type = f_type[5:-1]
			if f_type in l:
				l.remove(f_type)
				top.append(f_type)
	return top

all_types = list(struct_infos)

prereq_chunks = [pull_prereqs(all_types)]
remaining = None
while remaining != []:
	remaining = pull_prereqs(prereq_chunks[len(prereq_chunks) - 1])
	if remaining != []:
		prereq_chunks.append(remaining)

for i in range(len(prereq_chunks) - 1, -1, -1):
	prereq_types += prereq_chunks[i]

for prereq_name in prereq_types:
	#print(prereq_name)
	reg_struct(prereq_name, struct_infos[prereq_name])
print("=====================================================================")

for type_name in struct_infos:
	if not type_name in prereq_types:
		reg_struct(type_name, struct_infos[type_name])


print("=====================================================================")

a = os.listdir("NintendoClients.wiki")
for name in a:
	if name.lower() in blacklist:
		continue
	is_proto =  re.search("Protocol(?:-[^.]+)?.md", name)

	if is_proto:
		with open("NintendoClients.wiki/"+name) as f:
			methods_pass(f)

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
	if struct_name == 'Structure': # WEW
		out_file.write("""
			function do_Structure(conn, tree, tvb, off, field_name)
				local Structure_container = tree:add(F.Structure, tvb(off, 0))
				Structure_container:set_text("Structure")
				return off + conn['struct_header_len']
			end
		""")
	elif struct_name == "RVConnectionData":
		out_file.write("""function do_RVConnectionData(conn, tree, tvb, off, field_name)
local RVConnectionData_container = tree:add(F.RVConnectionData, tvb(off, 0))
	RVConnectionData_container:set_text("RVConnectionData")
	off = do_Structure(conn, RVConnectionData_container, tvb, off, 'RVConnectionData_Base')
off, RVConnectionData_m_urlRegularProtocols = do_StationURL(conn, RVConnectionData_container, tvb, off, 'RVConnectionData_m_urlRegularProtocols')
-- list !! byte
	local RVConnectionData_m_lstSpecialProtocols_len = tvb(off, 4):le_uint()
	subRVConnectionData_container = RVConnectionData_container:add_le(F.RVConnectionData_m_lstSpecialProtocols_len, tvb(off,4))
	off = off + 4
	for i=1,RVConnectionData_m_lstSpecialProtocols_len do
	off, RVConnectionData_m_lstSpecialProtocols_item = do_byte(conn, subRVConnectionData_container, tvb, off, 'RVConnectionData_m_lstSpecialProtocols_item')

	end
	
	off, RVConnectionData_m_urlSpecialProtocols = do_StationURL(conn, RVConnectionData_container, tvb, off, 'RVConnectionData_m_urlSpecialProtocols')
	
	if conn['version'] == 1 then
		off = off + 8 -- skip date
	end

return off
end
""")
	else:
		out_file.write(struct_funcs[struct_name] + "\n")

out_file.write("local info = {\n")
out_file.write(proto_info)
out_file.write("}\nreturn info")
out_file.close()
