global proxy_alerted: set[addr] = set();         
global srcIP: table[addr] of set[string] = table(); 

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    
    if (is_orig && name == "USER-AGENT")
    {
        local src: addr = c$id$orig_h;
        local lowerCase: string = to_lower(value);

        if (src !in srcIP)
            srcIP[src] = set();

        add srcIP[src][lowerCase];

        if (|srcIP[src]| >= 3 && src !in proxy_alerted)
        {
            print fmt("%s is a proxy", src);
            add proxy_alerted[src];
        }
    }
}
