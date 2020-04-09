type IP_useragent: record {
    address:addr;
    useragent: set[string];
};
global x: set[IP_useragent];
global proxy:set[addr];
global sourceIP:set[addr];

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	local UA=to_lower(value);
	local matchorig:bool=F;
	local matchresp:bool=F;
	for(e in x)
	{
		if(c$id$orig_h==e$address)
		{
			matchorig=T;
			if(!(UA in e$useragent))
			{
				add e$useragent[UA];
				if(|e$useragent|>=3)
				{
					add proxy[c$id$orig_h];
					delete sourceIP[c$id$orig_h];
				}
			}
			break;
		}		
	}
	
	
	
	if(matchorig==F)
	{
		local NewUA:set[string];
		add NewUA[UA];
		local Q:IP_useragent;
		Q$useragent=NewUA;
		Q$address=c$id$orig_h;		
		add x[Q];		
		add sourceIP[c$id$orig_h];
	}  	
}
event zeek_done() 
{
	for(e in proxy)
		print fmt("%s is a proxy",e);
	for(e in sourceIP)
		print fmt("%s is a sourceIP",e);
}
