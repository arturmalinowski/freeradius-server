function tprint (tbl, indent)
  if not indent then indent = 0 end
  for k, v in pairs(tbl) do
    formatting = string.rep("  ", indent) .. k .. ": "
    if type(v) == "table" then
      print(formatting)
      tprint(v, indent+1)
    else
      print(formatting .. v)
    end
  end
end


function authenticate()

end

function authorize()



for i in request['user-name'].next_iter() do 
	print(i)
end

for i in request['user-name'].next_iter() do 
	print(i)
end
	--tprint(get_attribute("user-name"))
	--tprint(get_attribute("user-password"))
	--tprint(get_attribute("tunnel-type", "2"))
	print(request)
	print(request['user-name'][0])
	print(request['user-name'].next_iter())
	print(request['user-name'].next_iter())
	--tprint(request['user-name'])
	--request['user-name'] = 'foo'
	--tprint(request['user-name'])
end
