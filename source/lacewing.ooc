use lacewing

Lacewing: class {
	version: extern(lw_version) static func -> CString
	fileLastModified: extern(lw_file_last_modified) static func (filename:CString) -> Int64
	fileExists: extern(lw_file_exists) static func (filename:CString) -> Bool
	fileSize: extern(lw_file_size) static func (filename:CString) -> SizeT
	pathExists: extern(lw_path_exists) static func (filename:CString) -> Bool
	tempPath: extern(lw_temp_path) static func (buffer:CString)
	guessMimetype: extern(lw_guess_mimetype) static func (filename:CString) -> CString
	md5: extern(lw_md5) static func (output:CString, input:CString, length:SizeT)
	md5Hex: extern(lw_md5_hex) static func (output:CString, input:CString, length:SizeT)
	sha1: extern(lw_sha1) static func (output:CString, input:CString, length:SizeT)
	sha1Hex: extern(lw_sha1_hex) static func (output:CString, input:CString, length:SizeT)
	dump: extern(lw_dump) static func (buffer:CString, size:SizeT)
	random: extern(lw_random) static func (buffer:CString, size:SizeT) -> Bool
}

LwThread: cover from lw_thread {
	new: extern(lw_thread_new) static func (name:CString, proc:Pointer) -> LwThread
	delete: extern(lw_thread_delete) func
	start: extern(lw_thread_start) func (param:Pointer)
	started: extern(lw_thread_started) func -> Bool
	join: extern(lw_thread_join) func -> Pointer
}

LwAddressHint: enum {
	tcp: extern (lw_addr_hint_tcp)
	udp: extern (lw_addr_hint_udp)
	ipv6: extern (lw_addr_hint_ipv6)
}

LwAddress: cover from lw_addr {
	new: extern(lw_addr_new) static func (hostname:CString, service:CString) -> LwAddress
	new: extern(lw_addr_new_port) static func ~port (hostname:CString, port:Long) -> LwAddress
	new: extern(lw_addr_new_hint) static func ~hint (hostname:CString, service:CString, hints:Long) -> LwAddress
	new: extern(lw_addr_new_port_hint) static func ~portHint (hostname:CString, port, hints:Long) -> LwAddress
	clone: extern(lw_addr_clone) func -> LwAddress
	delete: extern(lw_addr_delete) func
	port: extern(lw_addr_port) func -> Long
	setPort: extern(lw_addr_set_port) func (port:Long)
	ready: extern(lw_addr_ready) func -> Bool
	resolve: extern(lw_addr_resolve) func -> LwError
	ipv6: extern(lw_addr_ipv6) func -> Bool
	equal: extern(lw_addr_equal) func (addr:LwAddress) -> Bool
	toString: extern(lw_addr_tostring) func -> CString
}

LwFilter: cover from lw_filter {
	new: extern(lw_filter_new) static func -> LwFilter
	delete: extern(lw_filter_delete) func
	copy: extern(lw_filter_copy) func -> LwFilter
	remote: extern(lw_filter_remote) func -> LwAddress
	setRemote: extern(lw_filter_set_remote) func (address:LwAddress)
	local: extern(lw_filter_local) func -> LwAddress
	setLocal: extern(lw_filter_set_local) func (address:LwAddress)
	localPort: extern(lw_filter_local_port) func -> Long
	setLocalPort: extern(lw_filter_set_local_port) func (port:Long)
	remotePort: extern(lw_filter_remote_port) func -> Long
	setRemotePort: extern(lw_filter_set_remote_port) func (port:Long)
	reuse: extern(lw_filter_reuse) func -> Bool
	setReuse: extern(lw_filter_set_reuse) func (Bool)
	ipv6: extern(lw_filter_ipv6) func -> Bool
	setIpv6: extern(lw_filter_set_ipv6) func (Bool)
}


LwPumpDef: cover from lw_pumpdef {
	add              : extern Pointer // Platform specific (see LwPump add)
	update_callbacks : extern Pointer // Platform specific (see LwPump updateCallbacks)
	remove           : extern Pointer // Func (pump:LwPump, watch:LwPumpWatch)
	post             : extern Pointer // Func (pump:LwPump, fn:Void*, param:Void*)
	cleanup          : extern Pointer // Func (pump:LwPump)
	outer_size : extern SizeT
}

version (windows) {
	Overlapped: cover from OVERLAPPED
	Handle: cover from HANDLE
}

LwPumpCallback: cover from Pointer // unix: Func(tag:Pointer)
                                   // windows: Func(tag:Pointer, Overlapped*, bytes:ULong, error:Int)

LwPump: cover from lw_pump {
	new: extern(lw_pump_new) static func (LwPumpDef*) -> LwPump
	getDef: extern(lw_pump_get_def) func -> LwPumpDef*
	outer: extern(lw_pump_outer) func -> Pointer
	inner: extern(lw_pump_inner) func (Pointer) -> LwPump
	delete: extern(lw_pump_delete) func
	addUser: extern(lw_pump_add_user) func
	removeUser: extern(lw_pump_remove_user) func
	inUse: extern(lw_pump_in_use) func -> Bool
	remove: extern(lw_pump_remove) func (watch:LwPumpWatch)
	post: extern(lw_pump_post) func (fn:Pointer, param:Pointer)
	
	//version (windows) {
	//	add: extern(lw_pump_add) func (pump:LwPump, h:Handle, tag:Pointer, cb:LwPumpCallback) -> LwPumpWatch
	//	updateCallbacks: extern(lw_pump_update_callbacks) func (pump:LwPump, LwPumpWatch, tag:Pointer, cb:LwPumpCallback) -> Void
	//} else {
	//	add: extern(lw_pump_add) func (pump:LwPump, fd:Int, tag:Pointer, onReadReady, onWriteReady:LwPumpCallback, edgeTriggered:Bool) -> LwPumpWatch
	//	updateCallbacks: extern(lw_pump_update_callbacks) func (pump:LwPump, watch:LwPumpWatch, tag:Pointer, onReadReady, onWriteReady:LwPumpCallback, edgeTriggered:Bool) -> Void
	//}
}

LwPumpWatch: cover from lw_pump_watch {}

LwEventPump: cover from lw_eventpump {
	new: extern(lw_eventpump_new) static func -> LwEventPump
	tick: extern(lw_eventpump_tick) func -> LwError
	startEventLoop: extern(lw_eventpump_start_eventloop) func -> LwError
	startSleepyTicking: extern(lw_eventpump_start_sleepy_ticking) func (onTickNeeded:Pointer/*Func(LwEventPump)*/)
	postEventLoopExit: extern(lw_eventpump_post_eventloop_exit) func
	// note: LwPump methods can be called through casting
}


/* For stream implementors*/
LwStreamDef: cover from lw_streamdef {
	sink_data      : extern Pointer // Func (stream:LwStream, buffer:CString , size:SizeT) -> SizeT
	sink_stream    : extern Pointer // Func (LwStream, source:LwStream, size:SizeT) -> SizeT
	retry          : extern Pointer // Func (stream:LwStream, when:Int)
	is_transparent : extern Pointer // Func (stream:LwStream) -> Bool
	close          : extern Pointer // Func (stream:LwStream, immediate:Bool) -> Bool
	bytes_left     : extern Pointer // Func (stream:LwStream) -> SizeT
	read           : extern Pointer // Func (stream:LwStream, bytes:SizeT) -> Void
	cleanup        : extern Pointer // Func (stream:LwStream)
	outer_size : extern SizeT
}

LwStreamRetry: enum {
	now: extern (lw_stream_retry_now)
	never: extern (lw_stream_retry_never)
	moreData: extern (lw_stream_retry_more_data)
}

LwStreamHookData: cover from Pointer // Func(LwStream, tag:Void*, buffer:CString, length:SizeT)
LwStreamHookClose: cover from Pointer // Func(LwStream, tag:Void*)

LwStream: cover from lw_stream {
	new: extern(lw_stream_new) static func (def:LwStreamDef*, pump:LwPump) -> LwStream
	getDef: extern(lw_stream_get_def) func -> LwStreamDef*
	delete: extern(lw_stream_delete) func
	bytesLeft: extern(lw_stream_bytes_left) func -> SizeT
	read: extern(lw_stream_read) func (bytes:SizeT)
	beginQueue: extern(lw_stream_begin_queue) func
	queued: extern(lw_stream_queued) func -> SizeT
	endQueue: extern(lw_stream_end_queue) func
	endQueueHb: extern(lw_stream_end_queue_hb) func (numHeadBuffers:Int, buffers:CString* , lengths:SizeT*)
	write: extern(lw_stream_write) func (buffer:CString, length:SizeT)
	writeText: extern(lw_stream_write_text) func (buffer:CString)
	writef: extern(lw_stream_writef) func (format:CString, args:...)
	writeStream: extern(lw_stream_write_stream) func (src:LwStream, size:SizeT, deleteWhenFinished:Bool)
	writeFile: extern(lw_stream_write_file) func (filename:CString)
	retry: extern(lw_stream_retry) func (when:Int)
	addFilterUpstream: extern(lw_stream_add_filter_upstream) func (filter:LwStream, deleteWithStream, closeTogether:Bool)
	addFilterDownstream: extern(lw_stream_add_filter_downstream) func (filter:LwStream, deleteWithStream, closeTogether:Bool)
	close: extern(lw_stream_close) func (immediate:Bool) -> Bool
	tag: extern(lw_stream_tag) func -> Void*
	setTag: extern(lw_stream_set_tag) func (tag:Void*)
	pump: extern(lw_stream_pump) func -> LwPump
	outer: extern(lw_stream_outer) func -> Void*
	data: extern(lw_stream_data) func (buffer:CString, size:SizeT)
	addHookClose: extern(lw_stream_add_hook_close) func (fn:LwStreamHookClose, tag:Void*)
	removeHookClose: extern(lw_stream_remove_hook_close) func (fn:LwStreamHookClose, tag:Void*)
	addHookData: extern(lw_stream_add_hook_data) func (fn:LwStreamHookData, tag:Void*)
	removeHookData: extern(lw_stream_remove_hook_data) func (fn:LwStreamHookData, tag:Void*)
}

LwFileDescriptor: cover from lw_fd

LwFileStream: cover from lw_fdstream {
	new: extern(lw_fdstream_new) static func (pump:LwPump) -> LwFileStream
	setFd: extern(lw_fdstream_set_fd) func (fd:LwFileDescriptor, watch:LwPumpWatch, autoClose:Bool)
	cork: extern(lw_fdstream_cork) func
	uncork: extern(lw_fdstream_uncork) func
	nagle: extern(lw_fdstream_nagle) func (nagle:Bool)
	valid: extern(lw_fdstream_valid) func -> Bool
}

LwFile: cover from lw_file {
	new: extern(lw_file_new) static func (pump:LwPump) -> LwFile
	new: extern(lw_file_new_open) static func ~open (pump:LwPump, filename, mode:CString) -> LwFile
	open: extern(lw_file_open) func (filename, mode:CString) -> Bool
	openTemp: extern(lw_file_open_temp) func -> Bool
	name: extern(lw_file_name) func -> CString
}

LwPipe: cover from LwStream {
	new: extern(lw_pipe_new) static func (pump:LwPump) -> LwPipe
}

LwTimerHookTick: cover from Pointer // Func(LwTimer)

LwTimer: cover from lw_timer {
	new: extern(lw_timer_new) static func (pump:LwPump) -> LwTimer
	delete: extern(lw_timer_delete) func
	start: extern(lw_timer_start) func (milliseconds:Long)
	started: extern(lw_timer_started) func -> Bool
	stop: extern(lw_timer_stop) func
	forceTick: extern(lw_timer_force_tick) func
	tag: extern(lw_timer_tag) func -> Pointer
	setTag: extern(lw_timer_set_tag) func (Pointer)
	onTick: extern(lw_timer_on_tick) func (LwTimerHookTick)
}

LwSync: cover from lw_sync {
	new: extern(lw_sync_new) static func -> LwSync
	delete: extern(lw_sync_delete) func
	lock: extern(lw_sync_lock) func
	release: extern(lw_sync_release) func
}

LwEvent: cover from lw_event {
	new: extern(lw_event_new) static func -> LwEvent
	delete: extern(lw_event_delete) func
	signal: extern(lw_event_signal) func
	unsignal: extern(lw_event_unsignal) func
	signalled: extern(lw_event_signalled) func -> Bool
	wait: extern(lw_event_wait) func (milliseconds:Long) -> Bool
	tag: extern(lw_event_tag) func -> Pointer
	setTag: extern(lw_event_set_tag) func (Pointer)
}

LwError: cover from lw_error {
	new : extern(lw_error_new ) static func -> LwError
	delete: extern(lw_error_delete) func
	add: extern(lw_error_add) func (Long)
	addf: extern(lw_error_addf) func (format:CString, ...)
	size: extern(lw_error_size) func -> SizeT
	tostring: extern(lw_error_tostring) func -> CString
	clone: extern(lw_error_clone) func -> LwError
	tag: extern(lw_error_tag) func -> Pointer
	setTag: extern(lw_error_set_tag) func (Pointer)
}

LwClientHookConnect    : cover from Pointer // Func (LwClient)
LwClientHookDisconnect : cover from Pointer // Func (LwClient)
LwClientHookData       : cover from Pointer // Func (LwClient, buffer:CString, size:Long)
LwClientHookError      : cover from Pointer // Func (LwClient, LwError)

LwClient: cover from lw_client {
	new: extern(lw_client_new) static func (pump:LwPump) -> LwClient
	connect: extern(lw_client_connect) func (host:CString, port:Long)
	connect_addr: extern(lw_client_connect_addr) func (address:LwAddress)
	disconnect: extern(lw_client_disconnect) func
	connected: extern(lw_client_connected) func -> Bool
	connecting: extern(lw_client_connecting) func -> Bool
	server_addr: extern(lw_client_server_addr) func -> LwAddress
	onConnect: extern(lw_client_on_connect) func (LwClientHookConnect)
	onDisconnect: extern(lw_client_on_disconnect) func (LwClientHookDisconnect)
	onData: extern(lw_client_on_data) func (LwClientHookData)
	onError: extern(lw_client_on_error) func (LwClientHookError)
}

LwServerHookConnect    : cover from Pointer // Func(LwServer, LwServerClient)
LwServerHookDisconnect : cover from Pointer // Func(LwServer, LwServerClient)
LwServerHookData       : cover from Pointer // Func(LwServer, LwServerClient, CString buffer, SizeT size)
LwServerHookError      : cover from Pointer // Func(LwServer, LwError)

LwServer: cover from lw_server {
	new: extern(lw_server_new) static func (pump:LwPump) -> LwServer
	delete: extern(lw_server_delete) func
	host: extern(lw_server_host) func (port:Long)
	hostFilter: extern(lw_server_host_filter) func (filter:LwFilter)
	unhost: extern(lw_server_unhost) func
	hosting: extern(lw_server_hosting) func -> Bool
	port: extern(lw_server_port) func -> Long
	loadCertFile: extern(lw_server_load_cert_file) func (filename, passphrase:CString) -> Bool
	loadSysCert: extern(lw_server_load_sys_cert) func (storeName, commonName, location:CString) -> Bool
	certLoaded: extern(lw_server_cert_loaded) func -> Bool
	canNpn: extern(lw_server_can_npn) func -> Bool
	addNpn: extern(lw_server_add_npn) func (protocol:CString)
	numClients: extern(lw_server_num_clients) func -> SizeT
	clientFirst: extern(lw_server_client_first) func -> LwServerClient
	tag: extern(lw_server_tag) func -> Pointer
	setTag: extern(lw_server_set_tag) func (Pointer)
	onConnect: extern(lw_server_on_connect) func (LwServer, LwServerHookConnect)
	onDisconnect: extern(lw_server_on_disconnect) func (LwServer, LwServerHookDisconnect)
	onData: extern(lw_server_on_data) func (LwServer, LwServerHookData)
	onError: extern(lw_server_on_error) func (LwServer, LwServerHookError)
}

LwServerClient: cover from lw_server_client {
	lw_server_client_npn: extern(lw_server_client_npn) func (client:LwServerClient) -> CString
	lw_server_client_addr: extern(lw_server_client_addr) func (client:LwServerClient) -> LwAddress
	lw_server_client_next: extern(lw_server_client_next) func (client:LwServerClient) -> LwServerClient
}

LwUdpHookData: cover from Pointer // Func (LwUdp, LwAddress, CString buffer, SizeT size)
LwUdpHookError: cover from Pointer // Func (LwUdp, LwError)

LwUdp: cover from lw_udp {
	new: extern(lw_udp_new) static func (pump:LwPump) -> LwUdp
	delete: extern(lw_udp_delete) func
	host: extern(lw_udp_host) func (port:Long)
	hostFilter: extern(lw_udp_host_filter) func (filter:LwFilter)
	hostAddr: extern(lw_udp_host_addr) func (address:LwAddress)
	hosting: extern(lw_udp_hosting) func -> Bool
	unhost: extern(lw_udp_unhost) func
	port: extern(lw_udp_port) func -> Long
	send: extern(lw_udp_send) func (address:LwAddress, buffer:CString, size:SizeT)
	onData: extern(lw_udp_on_data) func (LwUdp, LwUdpHookData)
	onError: extern(lw_udp_on_error) func (LwUdp, LwUdpHookError)
}
	
LwFlashPolicyHookError: cover from Pointer // Func (LwFlashPolicy, LwError)

LwFlashPolicy: cover from lw_flashpolicy {
	new: extern(lw_flashpolicy_new) static func (pump:LwPump) -> LwFlashPolicy
	delete: extern(lw_flashpolicy_delete) func ()
	host: extern(lw_flashpolicy_host) func (filename:CString)
	hostFilter: extern(lw_flashpolicy_host_filter) func (filename:CString, filter:LwFilter)
	unhost: extern(lw_flashpolicy_unhost) func
	hosting: extern(lw_flashpolicy_hosting) func -> Bool
	onError: extern(lw_flashpolicy_on_error) func (LwFlashPolicyHookError)
}

LwWebServ: cover from lw_ws {
	new: extern(lw_ws_new) static func (pump:LwPump) -> LwWebServ
	delete: extern(lw_ws_delete) func
	host: extern(lw_ws_host) func (port:Long)
	hostSecure: extern(lw_ws_host_secure) func (port:Long)
	hostFilter: extern(lw_ws_host_filter) func (filter:LwFilter)
	hostSecureFilter: extern(lw_ws_host_secure_filter) func (filter:LwFilter)
	unhost: extern(lw_ws_unhost) func
	unhostSecure: extern(lw_ws_unhost_secure) func
	hosting: extern(lw_ws_hosting) func -> Bool
	hostingSecure: extern(lw_ws_hosting_secure) func -> Bool
	port: extern(lw_ws_port) func -> Long
	portSecure: extern(lw_ws_port_secure) func -> Long
	loadCertFile: extern(lw_ws_load_cert_file) func (filename, passphrase:CString) -> Bool
	loadSysCert: extern(lw_ws_load_sys_cert) func (storeName, commonName, location:CString) -> Bool
	certLoaded: extern(lw_ws_cert_loaded) func -> Bool
	sessionClose: extern(lw_ws_session_close) func (id:CString)
	enableManualFinish: extern(lw_ws_enable_manual_finish) func
	idleTimeout: extern(lw_ws_idle_timeout) func -> Long
	setIdleTimeout: extern(lw_ws_set_idle_timeout) func (seconds:Long)
	
	onGet: extern(lw_ws_on_get) func (LsWebServHookGet)
	onPost: extern(lw_ws_on_post) func (LsWebServHookPost)
	onHead: extern(lw_ws_on_head) func (LsWebServHookHead)
	onError: extern(lw_ws_on_error) func (LsWebServHookError)
	onDisconnect: extern(lw_ws_on_disconnect) func (LsWebServHookDisconnect)
	onUploadStart: extern(lw_ws_on_upload_start) func (LsWebServHookUploadStart)
	onUploadChunk: extern(lw_ws_on_upload_chunk) func (LsWebServHookUploadChunk)
	onUploadDone: extern(lw_ws_on_upload_done) func (LsWebServHookUploadDone)
	onUploadPost: extern(lw_ws_on_upload_post) func (LsWebServHookUploadPost)
}

LsWebServHookGet         : cover from Pointer // Func (serv:LwWebServ, req:LwWebServReq)
LsWebServHookPost        : cover from Pointer // Func (serv:LwWebServ, req:LwWebServReq)
LsWebServHookHead        : cover from Pointer // Func (serv:LwWebServ, req:LwWebServReq)
LsWebServHookError       : cover from Pointer // Func (serv:LwWebServ, err:LwError)
LsWebServHookDisconnect  : cover from Pointer // Func (serv:LwWebServ, req:LwWebServReq)
LsWebServHookUploadStart : cover from Pointer // Func (serv:LwWebServ, req:LwWebServReq, upload:LwWebServUpload)
LsWebServHookUploadChunk : cover from Pointer // Func (serv:LwWebServ, req:LwWebServReq, upload:LwWebServUpload, buffer:CString, size:SizeT)
LsWebServHookUploadDone  : cover from Pointer // Func (serv:LwWebServ, req:LwWebServReq, upload:LwWebServUpload)
LsWebServHookUploadPost  : cover from Pointer // Func (serv:LwWebServ, req:LwWebServReq, uploads:LwWebServUpload*, num:SuzeT)

LwWebServReq: cover from lw_ws_req {
	addr: extern(lw_ws_req_addr) func -> LwAddress
	secure: extern(lw_ws_req_secure) func -> Bool
	url: extern(lw_ws_req_url) func -> CString
	hostname: extern(lw_ws_req_hostname) func -> CString
	disconnect: extern(lw_ws_req_disconnect) func 
	setRedirect: extern(lw_ws_req_set_redirect) func (url:CString)
	status: extern(lw_ws_req_status) func (code:Long, message:CString)
	setMimetype: extern(lw_ws_req_set_mimetype) func (mimetype:CString)
	setMimetype: extern(lw_ws_req_set_mimetype_ex) func ~ex (mimetype, charset:CString)
	guessMimetype: extern(lw_ws_req_guess_mimetype) func (filename:CString)
	finish: extern(lw_ws_req_finish) func
	lastModified: extern(lw_ws_req_last_modified) func -> Int64
	setLastModified: extern(lw_ws_req_set_last_modified) func (Int64)
	setUnmodified: extern(lw_ws_req_set_unmodified) func
	setHeader: extern(lw_ws_req_set_header) func (name, value:CString)
	addHeader: extern(lw_ws_req_add_header) func (name, value:CString)
	header: extern(lw_ws_req_header) func (name:CString) -> CString
	headerFirst: extern(lw_ws_req_hdr_first) func -> LwWebServReqHeader
	GETFirst: extern(lw_ws_req_GET_first) func -> LwWebServReqParam
	POSTFirst: extern(lw_ws_req_POST_first) func -> LwWebServReqParam
	cookieFirst: extern(lw_ws_req_cookie_first) func -> LwWebServReqCookie
	setCookie: extern(lw_ws_req_set_cookie) func (name, value:CString)
	setCookieAttr: extern(lw_ws_req_set_cookie_attr) func (name, value, attributes:CString)
	getCookie: extern(lw_ws_req_get_cookie) func (name:CString) -> CString
	sessionId: extern(lw_ws_req_session_id) func -> CString
	sessionWrite: extern(lw_ws_req_session_write) func (name, value:CString)
	sessionRead: extern(lw_ws_req_session_read) func (name:CString) -> CString
	sessionClose: extern(lw_ws_req_session_close) func
	sessionFirst: extern(lw_ws_req_session_first) func -> LwWebServSessionItem
	GET: extern(lw_ws_req_GET) func (name:CString) -> CString
	POST: extern(lw_ws_req_POST) func (name:CString) -> CString
	body: extern(lw_ws_req_body) func -> CString
	disableCache: extern(lw_ws_req_disable_cache) func
	idleTimeout: extern(lw_ws_req_idle_timeout) func -> Long
	setIdleTimeout: extern(lw_ws_req_set_idle_timeout) func (seconds:Long)
}
LwWebServReqHeader: cover from lw_ws_req_hdr {
	name: extern(lw_ws_req_hdr_name) func -> CString
	value: extern(lw_ws_req_hdr_value) func -> CString
	next: extern(lw_ws_req_hdr_next) func -> LwWebServReqHeader
}
LwWebServReqParam: cover from lw_ws_req_param {
	name: extern(lw_ws_req_param_name) func -> CString
	value: extern(lw_ws_req_param_value) func -> CString
	next: extern(lw_ws_req_param_next) func -> LwWebServReqParam
}
LwWebServReqCookie: cover from lw_ws_req_cookie {
	name: extern(lw_ws_req_cookie_name) func -> CString
	value: extern(lw_ws_req_cookie_value) func -> CString
	next: extern(lw_ws_req_cookie_next) func -> LwWebServReqCookie
}
LwWebServUpload: cover from lw_ws_upload {
	formElName: extern(lw_ws_upload_form_el_name) func -> CString
	filename: extern(lw_ws_upload_filename) func -> CString
	header: extern(lw_ws_upload_header) func (name:CString) -> CString
	setAutosave: extern(lw_ws_upload_set_autosave) func
	autosaveFname: extern(lw_ws_upload_autosave_fname) func -> CString
	headerFirst: extern(lw_ws_upload_hdr_first) func -> LwWebServUploadHeader
}
LwWebServUploadHeader: cover from lw_ws_upload_hdr {
	name: extern(lw_ws_upload_hdr_name) func -> CString
	value: extern(lw_ws_upload_hdr_value) func -> CString
	next: extern(lw_ws_upload_hdr_next) func -> LwWebServUploadHeader
}
LwWebServSession: cover from lw_ws_session {}

LwWebServSessionItem: cover from lw_ws_sessionitem {
	name: extern(lw_ws_sessionitem_name) func -> CString
	value: extern(lw_ws_sessionitem_value) func -> CString
	next: extern(lw_ws_sessionitem_next) func -> LwWebServSessionItem
}
