use lacewing
import text/StringTokenizer
import structs/ArrayList
import math/Random

nick := "Gunter"
channel := "#bottestroom"
server := "irc.centralchat.net"
port := 6667
connected? := false

pump: LwEventPump
irc: LwClient

main: func {
	pump = LwEventPump new()

	irc = LwClient new(pump)
	irc onConnect(onConnect&)
	irc onData(onData&)

	irc connect(server, port)
	pump startEventLoop()

	irc delete()
	pump delete()
}

handle: func (msg:Message) {
	match (msg command) {
		case "MODE" =>
			if (!connected?) {
				connected? = true
				irc writef("JOIN %s\r\n", channel)
			}
		case "PING" =>
			irc writef("PONG :%s\r\n", msg tail)
		case "PRIVMSG" =>
			if (msg tail == "!roulette") roulette(msg)
	}
}

roulette: func (msg:Message) {
	reply:String
	if (Random randInt(1,6) == 6)
		reply = "*BANG*, " + msg nick + " is dead!"
	else reply = "*click*, " + msg nick + " is still alive."
	
	irc writef("PRIVMSG %s :%s\r\n", channel, reply)
}


onConnect: func (irc:LwClient) {
	irc writef("NICK %s\r\n", nick)
	irc writef("USER %s %s %s :ooc irc bot\r\n", nick, nick, nick)
}

onData: func (irc:LwClient, buffer:CString, size:Long) {
	messages := String new(buffer, size) split("\r\n")
	for (str in messages) {
		if (str != "") {
			str println()
			handle(Message new(str))
		}
	}
}

/**
 * Parses an irc message of the form
 * :nick!cloak COMMAND param1 param2 ... :tail
 */
Message: class {

	nick, cloak, command, tail: String
	params: ArrayList<String>

	init: func (msg:String) {
		i, j : Int
		if (msg startsWith?(':')) { 
			i = msg indexOf('!')
			j = msg indexOf(' ')
			nick = msg substring(1, i)
			cloak = msg substring(i+1, j)
			msg = msg substring(j+1)
		}

		i = msg indexOf(" :")
		if (i != -1) {
			tail = msg substring(i+2)
			msg = msg substring(0, i)
		}

		params = msg split(' ')
		command = params removeAt(0)
	}
}