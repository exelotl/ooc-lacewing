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
	trace: extern(lw_trace) static func (format:CString, ...)
	dump: extern(lw_dump) static func (buffer:CString, size:SizeT)
	random: extern(lw_random) static func (buffer:CString, size:SizeT) -> Bool
}

/**
 * Cross-platform facility for starting and joining a named thread (not likely to be used in ooc code)
 * It may be a good idea to compile lacewing with pthreads, to avoid conflicts with ooc's garbage collector
 *  (e.g. if the GC tries to collect an object created in a callback from lacewing's own internal threads)
 */
LwThread: cover from lw_thread {
	new: extern(lw_thread_new) static func (name:CString, proc:Pointer) -> LwThread
	delete: extern(lw_thread_delete) func
	start: extern(lw_thread_start) func (param:Pointer)
	started: extern(lw_thread_started) func -> Bool
	join: extern(lw_thread_join) func -> Pointer
	tag: extern(lw_thread_tag) func -> Pointer
	setTag: extern(lw_thread_set_tag) func (tag:Pointer)
}

LwAddressType: enum {
	tcp: extern(lw_addr_type_tcp)
	udp: extern(lw_addr_type_udp)
}

LwAddressHint: enum {
	ipv6: extern(lw_addr_hint_ipv6)
}

/**
 * Represents the address of a remote host.
 */
LwAddress: cover from lw_addr {
	new: extern(lw_addr_new) static func (hostname:CString, service:CString) -> LwAddress
	new: extern(lw_addr_new_port) static func ~port (hostname:CString, port:Long) -> LwAddress
	new: extern(lw_addr_new_hint) static func ~hint (hostname:CString, service:CString, hints:Long) -> LwAddress
	new: extern(lw_addr_new_port_hint) static func ~portHint (hostname:CString, port, hints:Long) -> LwAddress
	clone: extern(lw_addr_clone) func -> LwAddress
	delete: extern(lw_addr_delete) func
	port: extern(lw_addr_port) func -> Long
	setPort: extern(lw_addr_set_port) func (port:Long)
	type: extern(lw_addr_type) func -> LwAddressType
	setType: extern(lw_addr_set_type) func (type:LwAddressType)
	ready: extern(lw_addr_ready) func -> Bool
	resolve: extern(lw_addr_resolve) func -> LwError
	ipv6: extern(lw_addr_ipv6) func -> Bool
	equal: extern(lw_addr_equal) func (addr:LwAddress) -> Bool
	toString: extern(lw_addr_tostring) func -> CString
	tag: extern(lw_addr_tag) func -> Pointer
	setTag: extern(lw_addr_set_tag) func (tag:Pointer)
}

/**
 * Describe where a server (LwServer, LwWebServ, LwUdp) should accept connections from.
 */
LwFilter: cover from lw_filter {
	new: extern(lw_filter_new) static func -> LwFilter
	delete: extern(lw_filter_delete) func
	clone: extern(lw_filter_clone) func -> LwFilter
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
	tag: extern(lw_filter_tag) func -> Pointer
	setTag: extern(lw_filter_set_tag) func (tag:Pointer)
}

/* For pump implementors */
LwPumpDef: cover from lw_pumpdef {
	add              : extern Pointer // Platform specific (see LwPump add)
	update_callbacks : extern Pointer // Platform specific (see LwPump updateCallbacks)
	remove           : extern Pointer // Func (pump:LwPump, watch:LwPumpWatch)
	post             : extern Pointer // Func (pump:LwPump, fn:Pointer, param:Pointer)
	cleanup          : extern Pointer // Func (pump:LwPump)
	tail_size : extern SizeT
}

version (windows) {
	Overlapped: cover from OVERLAPPED
	Handle: cover from HANDLE
}

/**
 * Base class, watches file descriptors for activity
 */
LwPump: cover from lw_pump {
	new: extern(lw_pump_new) static func (LwPumpDef*) -> LwPump
	getDef: extern(lw_pump_get_def) func -> LwPumpDef*
	tail: extern(lw_pump_tail) func -> Pointer
	fromTail: extern(lw_pump_from_tail) func (Pointer) -> LwPump
	delete: extern(lw_pump_delete) func
	addUser: extern(lw_pump_add_user) func
	removeUser: extern(lw_pump_remove_user) func
	inUse: extern(lw_pump_in_use) func -> Bool
	remove: extern(lw_pump_remove) func (watch:LwPumpWatch)
	post: extern(lw_pump_post) func (fn:Pointer, param:Pointer)
	tag: extern(lw_pump_tag) func -> Pointer
	setTag: extern(lw_pump_set_tag) func (tag:Pointer)
}

version (windows) {
	extend LwPump {
		add: extern(lw_pump_add) func (pump:LwPump, h:Handle, tag:Pointer, cb:LwPumpCallback) -> LwPumpWatch
		updateCallbacks: extern(lw_pump_update_callbacks) func (pump:LwPump, watch:LwPumpWatch, tag:Pointer, cb:LwPumpCallback) -> Void
	}
} else {
	extend LwPump {
		add: extern(lw_pump_add) func (pump:LwPump, fd:Int, tag:Pointer, onReadReady, onWriteReady:LwPumpCallback, edgeTriggered:Bool) -> LwPumpWatch
		updateCallbacks: extern(lw_pump_update_callbacks) func (pump:LwPump, watch:LwPumpWatch, tag:Pointer, onReadReady, onWriteReady:LwPumpCallback, edgeTriggered:Bool) -> Void
	}
}

LwPumpCallback: cover from Pointer // unix: Func(tag:Pointer)
                                   // windows: Func(tag:Pointer, Overlapped*, bytes:ULong, error:Int)

LwPumpWatch: cover from lw_pump_watch

/**
 * Default implementation of LwPump. Has several modes of operation:
 *   tick - poll aggressively (suited to a game loop)
 *   startEventLoop - blocks forever (suited to console applications and daemons)
 *   startSleepyTicking - enables a threaded callback to request the application call tick() as soon as possible
 */
LwEventPump: cover from lw_eventpump extends LwPump {
	new: extern(lw_eventpump_new) static func -> LwEventPump
	tick: extern(lw_eventpump_tick) func -> LwError
	startEventLoop: extern(lw_eventpump_start_eventloop) func -> LwError
	startSleepyTicking: extern(lw_eventpump_start_sleepy_ticking) func (onTickNeeded:Pointer/*Func(LwEventPump)*/)
	postEventLoopExit: extern(lw_eventpump_post_eventloop_exit) func
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
	tail_size : extern SizeT
}

LwStreamRetry: enum {
	now: extern (lw_stream_retry_now)
	never: extern (lw_stream_retry_never)
	moreData: extern (lw_stream_retry_more_data)
}

/**
 * Base class for any object capable of I/O.
 */
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
	write: func ~oocString (str:String) { write(str, str size) }
	writef: func (str:String, args:...) {
		write(str format(args))
	}
	writeStream: extern(lw_stream_write_stream) func (src:LwStream, size:SizeT, deleteWhenFinished:Bool)
	writeFile: extern(lw_stream_write_file) func (filename:CString)
	retry: extern(lw_stream_retry) func (when:Int)
	addFilterUpstream: extern(lw_stream_add_filter_upstream) func (filter:LwStream, deleteWithStream, closeTogether:Bool)
	addFilterDownstream: extern(lw_stream_add_filter_downstream) func (filter:LwStream, deleteWithStream, closeTogether:Bool)
	close: extern(lw_stream_close) func (immediate:Bool) -> Bool
	tag: extern(lw_stream_tag) func -> Pointer
	setTag: extern(lw_stream_set_tag) func (tag:Pointer)
	pump: extern(lw_stream_pump) func -> LwPump
	tail: extern(lw_stream_tail) func -> Pointer
	fromTail: extern(lw_steam_from_tail) func (Pointer)
	data: extern(lw_stream_data) func (buffer:CString, size:SizeT)
	addHookClose: extern(lw_stream_add_hook_close) func (fn:LwStreamHookClose, tag:Pointer)
	removeHookClose: extern(lw_stream_remove_hook_close) func (fn:LwStreamHookClose, tag:Pointer)
	addHookData: extern(lw_stream_add_hook_data) func (fn:LwStreamHookData, tag:Pointer)
	removeHookData: extern(lw_stream_remove_hook_data) func (fn:LwStreamHookData, tag:Pointer)
}

LwStreamHookData: cover from Pointer // Func(LwStream, tag:Pointer, buffer:CString, length:SizeT)
LwStreamHookClose: cover from Pointer // Func(LwStream, tag:Pointer)

LwFileDescriptor: cover from lw_fd

/**
 * Implementation of LwStream over a file descriptor (or a file HANDLE on Windows)
 */
LwFDStream: cover from lw_fdstream extends LwStream {
	new: extern(lw_fdstream_new) static func (pump:LwPump) -> LwFDStream
	setFd: extern(lw_fdstream_set_fd) func (fd:LwFileDescriptor, watch:LwPumpWatch, autoClose:Bool)
	cork: extern(lw_fdstream_cork) func
	uncork: extern(lw_fdstream_uncork) func
	nagle: extern(lw_fdstream_nagle) func (nagle:Bool)
	valid: extern(lw_fdstream_valid) func -> Bool
}

/**
 * LwFDStream providing access to named files.
 */
LwFile: cover from lw_file extends LwFDStream {
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
	toString: extern(lw_error_tostring) func -> CString
	clone: extern(lw_error_clone) func -> LwError
	tag: extern(lw_error_tag) func -> Pointer
	setTag: extern(lw_error_set_tag) func (Pointer)
}

/**
 * TCP socket client, driven by a LwPump.
 */
LwClient: cover from lw_client extends LwFDStream {
	new: extern(lw_client_new) static func (pump:LwPump) -> LwClient
	connect: extern(lw_client_connect) func (host:CString, port:Long)
	connect: extern(lw_client_connect_addr) func ~addr (address:LwAddress)
	disconnect: extern(lw_client_disconnect) func
	connected: extern(lw_client_connected) func -> Bool
	connecting: extern(lw_client_connecting) func -> Bool
	serverAddr: extern(lw_client_server_addr) func -> LwAddress
	tag: extern(lw_client_tag) func -> Pointer
	setTag: extern(lw_client_set_tag) func (tag:Pointer)
	onConnect: extern(lw_client_on_connect) func (LwClientHookConnect)
	onDisconnect: extern(lw_client_on_disconnect) func (LwClientHookDisconnect)
	onData: extern(lw_client_on_data) func (LwClientHookData)
	onError: extern(lw_client_on_error) func (LwClientHookError)
}

LwClientHookConnect    : cover from Pointer // Func (LwClient)
LwClientHookDisconnect : cover from Pointer // Func (LwClient)
LwClientHookData       : cover from Pointer // Func (LwClient, buffer:CString, size:Long)
LwClientHookError      : cover from Pointer // Func (LwClient, LwError)

/**
 * TCP socket server, driven by a LwPump.
 */
LwServer: cover from lw_server {
	new: extern(lw_server_new) static func (pump:LwPump) -> LwServer
	delete: extern(lw_server_delete) func
	host: extern(lw_server_host) func (port:Long)
	host: extern(lw_server_host_filter) func ~filter (filter:LwFilter)
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
	setTag: extern(lw_server_set_tag) func (tag:Pointer)
	onConnect: extern(lw_server_on_connect) func (LwServerHookConnect)
	onDisconnect: extern(lw_server_on_disconnect) func (LwServerHookDisconnect)
	onData: extern(lw_server_on_data) func (LwServerHookData)
	onError: extern(lw_server_on_error) func (LwServerHookError)
}

LwServerHookConnect    : cover from Pointer // Func(LwServer, LwServerClient)
LwServerHookDisconnect : cover from Pointer // Func(LwServer, LwServerClient)
LwServerHookData       : cover from Pointer // Func(LwServer, LwServerClient, CString buffer, SizeT size)
LwServerHookError      : cover from Pointer // Func(LwServer, LwError)

/**
 * Represents a remote client connected to a LwServer.
 */
LwServerClient: cover from lw_server_client extends LwFDStream {
	npn: extern(lw_server_client_npn) func -> CString
	addr: extern(lw_server_client_addr) func -> LwAddress
	next: extern(lw_server_client_next) func -> LwServerClient
}

/**
 * LwEventPump-driven connectionless datagram support.
 */
LwUdp: cover from lw_udp {
	new: extern(lw_udp_new) static func (pump:LwPump) -> LwUdp
	delete: extern(lw_udp_delete) func
	host: extern(lw_udp_host) func (port:Long)
	host: extern(lw_udp_host_filter) func ~filter (filter:LwFilter)
	host: extern(lw_udp_host_addr) func ~addr (address:LwAddress)
	hosting: extern(lw_udp_hosting) func -> Bool
	unhost: extern(lw_udp_unhost) func
	port: extern(lw_udp_port) func -> Long
	send: extern(lw_udp_send) func (address:LwAddress, buffer:CString, size:SizeT)
	tag: extern(lw_udp_tag) func -> Pointer
	setTag: extern(lw_udp_set_tag) func (tag:Pointer)
	onData: extern(lw_udp_on_data) func (LwUdpHookData)
	onError: extern(lw_udp_on_error) func (LwUdpHookError)
}

LwUdpHookData: cover from Pointer // Func (udp:LwUdp, address:LwAddress, buffer:CString, size:SizeT)
LwUdpHookError: cover from Pointer // Func (udp:LwUdp, error:LwError)

/**
 * Host a socket policy file server for Adobe Flash Player clients.
 */
LwFlashPolicy: cover from lw_flashpolicy {
	new: extern(lw_flashpolicy_new) static func (pump:LwPump) -> LwFlashPolicy
	delete: extern(lw_flashpolicy_delete) func ()
	host: extern(lw_flashpolicy_host) func (filename:CString)
	host: extern(lw_flashpolicy_host_filter) func ~filter (filename:CString, filter:LwFilter)
	unhost: extern(lw_flashpolicy_unhost) func
	hosting: extern(lw_flashpolicy_hosting) func -> Bool
	tag: extern(lw_flashpolicy_tag) func -> Pointer
	setTag: extern(lw_flashpolicy_set_tag) func (tag:Pointer)
	onError: extern(lw_flashpolicy_on_error) func (LwFlashPolicyHookError)
}
	
LwFlashPolicyHookError: cover from Pointer // Func (LwFlashPolicy, LwError)

/**
 * Embeddable, flexible HTTP server.
 */
LwWebServ: cover from lw_ws {
	new: extern(lw_ws_new) static func (pump:LwPump) -> LwWebServ
	delete: extern(lw_ws_delete) func
	host: extern(lw_ws_host) func (port:Long)
	host: extern(lw_ws_host_filter) func ~filter (filter:LwFilter)
	hostSecure: extern(lw_ws_host_secure) func (port:Long)
	hostSecure: extern(lw_ws_host_secure_filter) func ~filter (filter:LwFilter)
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
	tag: extern(lw_ws_tag) func -> Pointer
	setTag: extern(lw_ws_set_tag) func (tag:Pointer)

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

/**
 * 
 */
LwWebServReq: cover from lw_ws_req extends LwStream {
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
