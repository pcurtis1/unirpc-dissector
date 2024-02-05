unirpc_protocol = Proto("UniRPC",  "UniRPC Protocol")

unirpc_protocol.fields = {}

unirpc_patt_check = ProtoField.int32("unirpc.patt_check", "patt_check", base.DEC)
unirpc_version = ProtoField.int32("unirpc.version", "version", base.DEC)
unirpc_seq_no = ProtoField.int32("unirpc.seq_no", "seq_no", base.DEC)
unirpc_length = ProtoField.int32("unirpc.length", "length", base.DEC)
unirpc_type = ProtoField.int32("unirpc.type", "type", base.DEC)
unirpc_ver_high = ProtoField.int32("unirpc.ver_high", "ver_high", base.DEC)
unirpc_compress = ProtoField.int32("unirpc.compress", "compress", base.DEC)
unirpc_encrypt = ProtoField.int32("unirpc.encrypt", "encrypt", base.DEC)
unirpc_future = ProtoField.int32("unirpc.future", "future", base.DEC)
unirpc_return_code = ProtoField.int32("unirpc.return_code", "return_code", base.DEC)
unirpc_arg_count = ProtoField.int32("unirpc.arg_count", "arg_count", base.DEC)
unirpc_proc_length = ProtoField.int32("unirpc.proc_length", "proc_length", base.DEC)

unirpc_arg_type = ProtoField.int32("unirpc.arg_type", "arg_type", base.DEC)

unirpc_protocol.fields = { unirpc_patt_check, unirpc_version, unirpc_seq_no, unirpc_length, unirpc_type, unirpc_ver_high, unirpc_compress, unirpc_encrypt, unirpc_future, unirpc_return_code, unirpc_arg_count, unirpc_proc_length }

function unirpc_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = unirpc_protocol.name

  local subtree = tree:add(unirpc_protocol, buffer(), "UniRPC Protocol Data")

  local _patt_check = buffer(0,1):uint()
  print("patt check" .. _patt_check)

  local _urpc_length = buffer(4,4):uint()
  local _arg_count = buffer(20,2):uint()

  print("TCP payload length: " .. length)
  print("UniRPC packet length: " .. _urpc_length)

  if length < _urpc_length + 24 then
	bytes_remaining = _urpc_length + 24 - length
  	print("bytes_remaining " .. bytes_remaining)
	  pinfo.desegment_len = bytes_remaining
	  return
  end

  local headerSubtree = subtree:add(unirpc_protocol, buffer(0,24), "Header")
  local payloadBuffer = buffer(24,_urpc_length)
  local argBuffer = payloadBuffer(0,_arg_count * 8)
  local dataBuffer = payloadBuffer(_arg_count*8,_urpc_length - (_arg_count*8))

  local payloadSubtree = subtree:add(unirpc_protocol, payloadBuffer, "Payload")

  local data_offset = 0

  for i=0,_arg_count-1 do
	  print ("arg"..i)
	  local arg_length_buf = payloadBuffer(i*8,4)
	  local arg_length = arg_length_buf:uint()
	  local arg_type_buf = payloadBuffer(i*8 + 4, 4)
	  local arg_type = arg_type_buf:uint()

	  local arg_data_buf_length = 4
	  local padding_length = 0

	  if (arg_type == 3 or arg_type == 4) then
		  arg_data_buf_length = arg_length

		  paddingLength = (4 - (arg_length % 4)) % 4
		  --arg_data_buf_length = arg_length + paddingLength
	  end

	  print ("length: "..arg_length..", type: "..arg_type.."paddint_length: "..padding_length)

          local argumentSubtree = payloadSubtree:add(unirpc_protocol, payloadBuffer(i*8, 8), "Argument")
	  local dataSubtree = argumentSubtree:add(unirpc_protocol, dataBuffer(data_offset, arg_data_buf_length), "Data")

	  data_offset = data_offset + arg_data_buf_length

	  -- get the length and type (each u32) of each argument.
  end
  
  headerSubtree:add(unirpc_patt_check, buffer(0,1))
  headerSubtree:add(unirpc_version, buffer(1,1))
  headerSubtree:add(unirpc_seq_no, buffer(2,2))
  headerSubtree:add(unirpc_length, buffer(4,4))
  headerSubtree:add(unirpc_type, buffer(8,4))
  headerSubtree:add(unirpc_ver_high, buffer(12,1))
  headerSubtree:add(unirpc_compress, buffer(13,1))
  headerSubtree:add(unirpc_encrypt, buffer(14,1))
  headerSubtree:add(unirpc_future, buffer(15,1))
  headerSubtree:add(unirpc_return_code, buffer(16,4))
  headerSubtree:add(unirpc_arg_count, buffer(20,2))
  headerSubtree:add(unirpc_proc_length, buffer(22,2))
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(31438, unirpc_protocol)
