use lacewing

get: func(webserver:LwWebServ, req:LwWebServReq) {
	req writef("Hello world from %s in ooc!", Lacewing version())
}

main: func {
	pump := LwEventPump new()
	webserver := LwWebServ new(pump)
	webserver onGet(get&) .host(8081)
	pump startEventLoop()
	
	webserver delete()
	pump delete()
}
