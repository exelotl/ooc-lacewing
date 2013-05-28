use lacewing

get: func(webserver:LwWebServ, req:LwWebServReq) {
	str := "Hello world from %s in ooc!" format(Lacewing version())
	(req as LwStream) write(str, str size)
}

main: func {
	pump := LwEventPump new()
	webserver := LwWebServ new(pump)
	webserver onGet(get&) .host(8081)
	pump startEventLoop()
	
	webserver delete()
	pump delete()
}
