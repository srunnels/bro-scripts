
signature rdp_server {
	ip-proto == tcp
	payload /\x03....\xd0/
	requires-reverse-signature rdp_client
	event "rdp"
	tcp-state responder
}

signature rdp_client {
	ip-proto == tcp
	payload /\x03....\xe0/
	tcp-state originator
}


