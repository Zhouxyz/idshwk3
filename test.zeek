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
		if(c$id$resp_h==e$address)
		{
			matchresp=T;
			if(!(UA in e$useragent))
			{
				add e$useragent[UA];
				if(|e$useragent|>=3)
				{
					add proxy[c$id$resp_h];
					delete sourceIP[c$id$resp_h];
				}
			}
			break;
		}
	}
	
	local NewUA:set[string];
	add NewUA[UA];
	local Q:IP_useragent;
	Q$useragent=NewUA;
	
	if(matchorig==F)
	{
		Q$address=c$id$orig_h;		
		add x[Q];		
		add sourceIP[c$id$orig_h];
	}  
	
	if(matchresp==F)
	{		
		Q$address=c$id$resp_h;
		add x[Q];	
		add sourceIP[c$id$resp_h];
	}  
}
event zeek_done() 
{
    print "proxy:";
	print proxy;
	print "sourceIP:";
	print sourceIP;
}
