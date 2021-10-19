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


def bad_lua_chars(s):
	return s.replace(" ", "_").replace("(","").replace(")","").replace(".","_").replace(",","_").replace("/","_")

class Type:
	def __init__(self, name):
		self.fields = []
		result = re.match("###? ([^\\(]+)(?:\\((\S+)\\))?", name)
		if result == None:
			print("????")

		self.name = bad_lua_chars(result[1].strip())
		if result[2] != None:
			self.base = delink(result[2])
			self.fields.append(('Base', self.base, None, None))
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
	types[struct_name] = lambda field_name, arg_name, struct_name=struct_name: f"off = do_{struct_name}(conn, tree, tvb, off, '{field_name}', '{arg_name}')"

	struct_length = 0
	func = f"function do_{struct_name}(conn, tree, tvb, off, field_unique_name, field_name)\n"

	func += f"""local {struct_name}_container = tree:add(F.{struct_name}, tvb(off, {struct_length}))
	{struct_name}_container:set_text(field_name .. " ({struct_name}):")
	"""

	for f in struct_info:
		# f[2] holds nex version
		# TODO: please just make this a struct
		if f[2] != None:
			func += f"if version_gt_eq(conn['nex_version'], {{{f[2].replace('.',',')}}}) then\n"
		func += dispatch_type(struct_name + "_" + f[0], f[0], f[1]).replace("tree", f"{struct_name}_container")
		if f[2] != None:
			func += "\nend\n"
			pass

	func += "\nreturn off\nend"

	struct_funcs[struct_name] = func

types = {}
type_funcs = {}
def reg_type(type_name, func):
	type_funcs[type_name] = f"function do_{type_name}(conn, tree, tvb, off, field_unique_name, field_name)\n" + func(type_name, type_name) + "\nend"
	def type_thunk(field_name, arg_name, type_name=type_name, func=func, extract=False):
		func(field_name, arg_name) # TODO: why?????
		return f"off, {field_name} = do_{type_name}(conn, tree, tvb, off, '{field_name}', '{arg_name}')"
	types[type_name] = type_thunk

def int_field(l, field_name, arg_name, signed=False):
	if signed:
		prefix = ""
	else:
		prefix = "u"
	proto_fields.append((field_name, arg_name, f"{prefix}int{l}", f"uint{l}"))
	func = f"tree:add_le(F[field_unique_name], tvb(off,{l//8}))"
	if l != 64:
		func += f"return off + {l//8}, tvb(off,{l//8}):le_{prefix}int()"
	else:
		func += f"return off + {l//8}"
	return func

def i32(field_name, arg_name):
	proto_fields.append((field_name, arg_name, 'int32', 'int32'))
	return f"""tree:add_le(F[field_unique_name], tvb(off,4))

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
	tree:add_le(F[field_unique_name.."_len"], tvb(off, {l//8}))
	if {field_name}_len ~= 0 then
		tree:add(F[field_unique_name.."_data"], tvb(off+{l//8}, {field_name}_len))
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
	tree:add_le(F[field_unique_name.. "_len"], tvb(off, 2))
	tree:add(F[field_unique_name.. "_data"], tvb(off+2, {field_name}_len))
	return off + 2 + {field_name}_len, tvb(off+2, {field_name}_len-1):string()"""

reg_type('String', do_string)
reg_type('StationURL', do_string)

def do_bool(field_name, arg_name):
	proto_fields.append((field_name, arg_name, "bool", "bool"))
	return f"""tree:add(F[field_unique_name], tvb(off,1))
	return off + 1, (tvb(off,1)~= 0)"""
reg_type('Bool', do_bool)

def do_float(l, field_name, arg_name):
	if l == 4:
		n = "float"
	elif l == 8:
		n = "double"
	proto_fields.append((field_name, arg_name, n, n))
	return f"""tree:add_le(F[field_unique_name], tvb(off,{l}))
	return off + {l}, tvb(off,{l}):le_float()"""
reg_type('Float', lambda a,b: do_float(4, a, b))
reg_type('Double', lambda a,b: do_float(8, a, b))

def do_list(field_name, arg_name, list_type, in_list=False):
	# todo: i hope i never get a list<list<list<object>>>
	loop_var_name = 'i' if not in_list else 'j'
	proto_fields.append((field_name+"_len", arg_name + " length", "uint32", "uint32"))
	return f"""local {field_name}_len = tvb(off, 4):le_uint()
	subtree = tree:add_le(F.{field_name}_len, tvb(off,4))
	off = off + 4
	for {loop_var_name}=1,{field_name}_len do
	""" + dispatch_type(field_name+"_item", arg_name, list_type).replace("tree", "subtree") + """
	end
	"""

def do_map(field_name, arg_name, map_types):
	loop_var_name = 'i'
	proto_fields.append((field_name+"_len", arg_name + " length", "uint32", "uint32"))
	return f"""local {field_name}_len = tvb(off, 4):le_uint()
	subtree = tree:add_le(F.{field_name}_len, tvb(off,4))
	off = off + 4
	for {loop_var_name}=1,{field_name}_len do
	""" + dispatch_type(field_name+"_key", arg_name, map_types[0]).replace("tree", "subtree") + "\n" + dispatch_type(field_name+"_value", arg_name, map_types[1]).replace("tree", "subtree") + """
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
			off = _G[type_func](conn, {field_name}_container, tvb, off, "{field_name}_data", "{arg_name}")
		else
			{field_name}_container:add(F.{field_name}_data_bytes, tvb(off, {field_name}_len))
			off = off + {field_name}_data_len
		end
	"""
	return func

def valid_type(type_name):
	if type_name in types:
		return True, type_name, False
	else:
		if type_name.startswith("Data<"):
			data_type = type_name[5:-1]
			if data_type in types:
				return True, data_type, False
			else:
				return False, data_type, False
		elif type_name.startswith("List<"):
			contained_type = type_name[5:-1]
			if contained_type in types:
				return True, type_name, True
			else:
				return False, type_name, True
		else:
			return False, type_name, False

def dispatch_type(field_unique_name, arg_name, arg_type):
	if arg_type.startswith("List"):
		in_list = False

		list_type = arg_type[5:-1]
		valid, type_name, in_list = valid_type(list_type)
		if not valid:
			# bail.
			print("Stubbed type {} in list".format(type_name))
			return "--[[ Stubbed! Missing type (in list) {}]]\n".format(type_name)

		return do_list(field_unique_name, arg_name, list_type, in_list) + "\n"
	elif arg_type.startswith("Map"):
		maybe_map_types = arg_type[4:-1]
		maybe_map_types = list(map(lambda a: a.strip(), maybe_map_types.split(",")))
		map_types = []
		for ty in maybe_map_types:
			valid, type_name, in_list = valid_type(ty)
			if valid:
				map_types.append(type_name)
			else:
				print("Stubbed type {} in map".format(type_name))
				return "--[[ Stubbed! Missing type (in map) {}]]\n".format(type_name)

		return do_map(field_unique_name, arg_name, map_types) + "\n"
	elif arg_type == 'Data' or arg_type.startswith("Data<"):
		if len(arg_type) > 4:
			data_type = arg_type[5:-1]
			if not data_type in types:
				print("Stubbed type {} in Data".format(data_type))
				return "--[[ Stubbed! Missing type (in Data) {}]]\n".format(data_type)
		return do_data(field_unique_name, arg_name, arg_type) + "\n"
	elif arg_type == 'Any' or arg_type.startswith("Any<"):
		if len(arg_type) > 3:
			data_type = arg_type[4:-1]
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
)
reg_struct('Data', Data_info)

Structure_info = (
	("Version", "Uint8", None),
	("Length", "Uint32", None)
)
reg_struct('Structure', Structure_info)

DataHeader_info = (
	("Base", "Structure", None),
)
reg_struct('DataHeader', DataHeader_info)

RVConnectionData_info = (
	('m_urlRegularProtocols', 'StationURL', None),
	('m_lstSpecialProtocols', 'List<byte>', None),
	('m_urlSpecialProtocols', 'StationURL', None)
)
reg_struct('RVConnectionData', RVConnectionData_info)

ResultRange_info = (
	('m_uiOffset', 'Uint32', None),
	('m_uiSize', 'Uint32', None)
)
reg_struct('ResultRange', ResultRange_info)


def lua_build_method(method_prefix, info):
	func = """function (conn, tree, tvb)
	local off = 0
"""
	for i in info:
		arg_type = fix_html(delink(i[0]))
		arg_name = delink(i[1])
		if arg_name == "%retval%":
			arg_name = "retval"

		field_unique_name = method_prefix + "_" + arg_name.replace(" ", "_")

		arg_detail = None
		if len(i) > 2:
			arg_detail = i[2]
		func += dispatch_type(field_unique_name, arg_name, arg_type)
		
	func += " end"
	return func

def lua_build_proto(header, cmds, method_infos, nested):
	result = re.search("([A-Za-z0-9 ]+) \\(([0-9A-Fa-fx?]+)\\)", header)
	# this gets the id reliably, but not the name
	# ie Data Store (0x73) > Splatoon 2
	# vs Data Store > SSBB4 (115)

	proto_name = result[1].strip()
	proto_name_safe = proto_name.replace(' ', '_')
	proto_id = result[2].strip()

	if nested:
		probably_name = header.split(">")[-1]
		result = re.search("([A-Za-z0-9 ]+)(?: \\(([0-9A-Fa-fx?]+)\\))?", probably_name)
		proto_name = result[1].strip()
		proto_name_safe = proto_name.replace(' ', '_')

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

	return """add_proto({},
	{{
		["nested"] = {},
		["name"] = "{}",
		["methods"] = {{
{}
		}}
	}})""".format(proto_id, "true" if nested else "false", proto_name, cmd_list)

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
				base = delink(re.search("This structure inherits from ([^|]+) \|", l)[1])

				if base == 'Data':
					base = 'DataHeader'

				current_type.base = base # lol
				current_type.fields.insert(0, ('Base2', base, None, None))

				table = True
				skip_table = True
				print("We got some weird inheritance!", base)
				#exit()
				continue
			else:
				table = True
				if should_parse_type:
					table_header = list(map(lambda a: a.strip(), filter(None, l.split("|"))))
					allowed_tables = [
						['Type','Name','Description'],
						['Type','Description'],
						['Type','Name'],
						['Type', 'Name', 'Only present on'],
						
					]
					if table_header not in allowed_tables:
						skip_table = True
				continue # Skip the table header..
		if table:
			if l == '': # End of table
				if not skip_table and should_parse_type:
					fixed = []
					for f_name, t_name, nex_version, rename_count in current_type.fields:
						if rename_count == None:
							fixed.append((f_name, t_name, nex_version))
						else:
							fixed.append((f_name + str(rename_count), t_name, nex_version))
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
					if '<br>' in row[1]:
						field_name = row[1].split("<br>")[0]
					else:
						field_name = row[1]
					field_name_safe = bad_lua_chars(delink(field_name))
					type_name_safe = fix_html(delink(row[0]))

					nex_version = None

					if 'Only present on' in table_header:
						loc = table_header.index('Only present on')
						result = re.match("NEX v(.*) and later", row[loc])
						if result:
							nex_version = result[1]

					rename_needed = False
					max_n = 0
					for i,f in enumerate(current_type.fields):
						if field_name_safe == f[0]:
							print("Field name collision!", f[0])
							rename_needed = True
							if len(f) < 3:
								max_n = 1
							else:
								if f[3] == None:
									max_n = 1
								else:
									max_n = f[3]
					if rename_needed:
						current_type.fields.append((field_name_safe, type_name_safe, nex_version, max_n + 1))
					else:
						current_type.fields.append((field_name_safe, type_name_safe, nex_version, None))
		else:
			if l == '# Types':
				should_parse_type = True
			elif l.startswith("## ") or l.startswith("### ") and should_parse_type:
				if sticky_skip_table:
					sticky_skip_table = False
					skip_table = False

				# Hack lmao
				if l == '## Request' or l == '## Response':
					skip_table = True
					sticky_skip_table = True
				else:
					# todo: sanitize type
					current_type = Type(l)
			

def methods_pass(f):
	global proto_info
	header = f.readline().strip()

	if "Pia Protocols" in header:
		return

	nested = False
	if len(header.split(">")) > 2:
		nested = True

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
	table_header = []
	skip_table = False

	for l in f.readlines():
		l = l.strip()
		if not table and l.startswith('|'):
			table = True
			table_header = list(map(lambda a: a.strip(), filter(None, l.split("|"))))
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

				if 'Description' in table_header:
					desc = row[table_header.index("Description")]
					if 'Only present on Switch' in desc:
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
						continue

					if meth.name == "ProcessNintendoNotificationEvent":
						meth.id = 1
					current_method = meth
					state = MethodRequest
				elif state == MethodResponse:
					# Maybe the method before is just missing info. That's fine.
					method_infos[current_method.id] = current_method

					current_method = Method(l)
					state = MethodRequest
			elif l.startswith("##"):
				if (state == MethodRequest and l != '## Request') or (state == MethodResponse and l != '## Response'):
					skip_table = True
				else:
					skip_table = False
			elif l.startswith('This method does not take any request data') or l.startswith('This method does not take any parameters'):
				state = MethodResponse
			elif l.startswith('This method does not return anything') or l.startswith("This method doesn't return anything") or l.startswith("No RMC response is sent."):
				state = SearchingForMethod
				if current_method.name == "ProcessNintendoNotificationEvent":
					method_infos[1] = current_method
					method_infos[2] = current_method
				else:
					method_infos[current_method.id] = current_method
			elif l.startswith("This method takes no parameters and doesn't return anything."):
				state = SearchingForMethod
				method_infos[current_method.id] = current_method
	if table:
		table = False

	proto_info += lua_build_proto(header, cmd_list, method_infos, nested=nested)+"\n"

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
			header = f.readline().strip()
			if "Pia Protocols" in header:
				continue
			types_pass(f)

print("=====================================================================")

prereq_types = []

def pull_prereqs(l):
	top = []
	for item in l[:]: # Copy the list!
		for f_name, f_type, nex_version in struct_infos[item]:
			if f_type.startswith("List"):
				f_type = f_type[5:-1]
			if f_type in l:
				l.remove(f_type)
				top.append(f_type)

			if f_type.startswith("Map"):
				f_types = list(map(lambda a: a.strip() ,f_type[4:-1].split(",")))
				if f_types[0] in l:
					l.remove(f_types[0])
					top.append(f_types[0])
				if f_types[1] in l:
					l.remove(f_types[1])
					top.append(f_types[1])
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
	if struct_name == 'Structure':
		out_file.write("""
			function do_Structure(conn, tree, tvb, off, field_name)
				local Structure_container = tree:add(F.Structure, tvb(off, 0))
				Structure_container:set_text("Structure")
				if conn['has_struct_headers'] then
					off, a = do_Uint8(conn, Structure_container, tvb, off, 'Structure_Version')
					off, b = do_Uint32(conn, Structure_container, tvb, off, 'Structure_Length')
				end
				return off
			end
		""")
	elif struct_name == "RVConnectionData":
		out_file.write("""function do_RVConnectionData(conn, tree, tvb, off, field_name)
local RVConnectionData_container = tree:add(F.RVConnectionData, tvb(off, 0))
	RVConnectionData_container:set_text("RVConnectionData")
	off = do_Structure(conn, RVConnectionData_container, tvb, off, 'RVConnectionData_Base')
off, RVConnectionData_m_urlRegularProtocols = do_StationURL(conn, RVConnectionData_container, tvb, off, 'RVConnectionData_m_urlRegularProtocols')
	local RVConnectionData_m_lstSpecialProtocols_len = tvb(off, 4):le_uint()
	subRVConnectionData_container = RVConnectionData_container:add_le(F.RVConnectionData_m_lstSpecialProtocols_len, tvb(off,4))
	off = off + 4
	for i=1,RVConnectionData_m_lstSpecialProtocols_len do
	off, RVConnectionData_m_lstSpecialProtocols_item = do_byte(conn, subRVConnectionData_container, tvb, off, 'RVConnectionData_m_lstSpecialProtocols_item')

	end
	
	off, RVConnectionData_m_urlSpecialProtocols = do_StationURL(conn, RVConnectionData_container, tvb, off, 'RVConnectionData_m_urlSpecialProtocols')
	
	if conn['prudp_version'] == 1 then
		off = off + 8 -- skip date
	end

return off
end
""")
	else:
		out_file.write(struct_funcs[struct_name] + "\n")

out_file.write("""
local info = {}
local nested_info = {}
function add_proto(id, tab)
	if not tab["nested"] then
		info[id] = tab
	else
		name = tab["name"]
		if not nested_info[name] then
			nested_info[name] = {}
		end

		nested_info[name][id] = tab
	end
end
	""")

#out_file.write("local info = {\n")
out_file.write(proto_info)
out_file.write("\nreturn info, nested_info")
out_file.close()
