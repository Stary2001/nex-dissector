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

types = {}
def u(l, field_name, arg_name):
	proto_fields.append((field_name, arg_name, "uint{}".format(l), "uint{}".format(l)))
	return f"""tree:add_le(F.{field_name}, tvb(off,{l//8}))
	off = off + {l//8}"""

def i32(field_name, arg_name):
	proto_fields.append((field_name, arg_name, 'int32', 'int32'))
	return f"""tree:add_le(F.{field_name}, tvb(off,4))
	off = off + 4"""
types['Int32'] = i32

types['Uint8'] = lambda a,b: u(8, a, b)
types['Uint16'] = lambda a,b: u(16, a, b)
types['Uint32'] = lambda a,b: u(32, a, b)
types['Uint64'] = lambda a,b: u(64, a, b)

types['PID'] = types['Uint32']
types['NEXDateTime'] = types['Uint64']

def buffer(l, field_name, arg_name):
	proto_fields.append((field_name+"_len", arg_name + " length", "uint{}".format(l), "Buffer"))
	proto_fields.append((field_name+"_data", arg_name + " data", "bytes", "Buffer"))

	return f"""local {field_name}_len = tvb(off,{l//8}):le_uint()
	tree:add_le(F.{field_name}_len, tvb(off, {l//8}))
	tree:add(F.{field_name}_data, tvb(off+{l//8}, len))
	off = off + {l//8}"""

types['Buffer'] = lambda a,b: buffer(32, a, b)
types['qBuffer'] = lambda a,b: buffer(16, a, b)

def do_string(field_name, arg_name):
	proto_fields.append((field_name+"_len", arg_name + " length", "uint16", "String"))
	proto_fields.append((field_name+"_data", arg_name + " data", "string", "String"))

	return f"""local {field_name}_len = tvb(off,2):le_uint()
	tree:add_le(F.{field_name}_len, tvb(off, 2))
	tree:add(F.{field_name}_data, tvb(off+2, {field_name}_len))
	off = off + 2 + {field_name}_len"""

types['String'] = do_string
types['StationURL'] = do_string

def do_bool(field_name, arg_name):
	proto_fields.append((field_name+"_len", arg_name, "bool", "bool"))
	return f"""tree:add(F.{field_name}, tvb(off,1))
	off = off + 1"""
types['Bool'] = do_bool

def do_list(name, arg_name, list_type):
	#print(name, list_type)
	#exit()
	return "--[[ Stubbed list. ]]"

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

		if arg_type.startswith("List"):
			list_type = arg_type[5:-1]
			if not list_type in types:
				# bail.
				print("Stubbed type {}".format(list_type))
				return "function (a, b) end --[[ Stubbed! Missing type (in list) {}]]".format(list_type)
			func += do_list(field_unique_name, arg_name, list_type) + "\n"
		else:
			if not arg_type in types:
				# bail.
				print("Stubbed type {}".format(arg_type))
				return "function (a, b) end --[[ Stubbed! Missing type {}]]".format(arg_type)
			else:
				func += types[arg_type](field_unique_name, arg_name) + "\n"
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
					#print(l)
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
								#print("Got correct header, stop skipping!!")
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

out_file.write("local info = {\n")
out_file.write(proto_info)
out_file.write("}\nreturn info")
out_file.close()