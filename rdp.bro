redef signature_files += "rdp.sig";

module RDP;

export {

	# This allows us to use RDP::LOG 
    redef enum Log::ID += { LOG };
	
    type Info: record {
		ts:          time     &log;
		uid:         string   &log;
		id:          conn_id  &log;
		# success:     bool     &log &default=F;
		
		last_size:   count    &default=0;
		last_check:  time     &default=network_time();
        num_checks:  count    &default=0;
        last_total:  count    &default=0;
        byte_vector: vector of count &default = vector(0,0,0,0,0);
        avg:         count    &log &default=0;
		# humps_seen:  count    &default=0;
		# plateau_measurements: count &default=0;
		# last_seen:   string   &default="plateau";
	};
	
	## Amount of time to monitor a connection for the second hump of data.
	const watch_for = 120secs;
}

redef record connection += { 
	rdp: Info &optional;
};

# Initialize the RDP logging stream
event bro_init()
      {
      Log::create_stream(RDP::LOG, [$columns=Info]);
      }

event dump_bytes(id: conn_id)
      {
      if ( ! connection_exists(id) )
         {
         print "No connection found";
         return;
         }
      local c = lookup_connection(id);

      # Poor man's FIFO
      c$rdp$byte_vector[0] = c$rdp$byte_vector[1];
      c$rdp$byte_vector[1] = c$rdp$byte_vector[2];
      c$rdp$byte_vector[2] = c$rdp$byte_vector[3];
      c$rdp$byte_vector[3] = c$rdp$byte_vector[4];
      c$rdp$byte_vector[4] = c$resp$num_bytes_ip - c$rdp$last_size;
      
      if (c$rdp$num_checks >= 4)
         {
         c$rdp$avg = (c$rdp$byte_vector[0] + c$rdp$byte_vector[1] + c$rdp$byte_vector[2] + c$rdp$byte_vector[3] + c$rdp$byte_vector[4] ) / 5;
         Log::write(RDP::LOG, c$rdp);
         }

      ++c$rdp$num_checks;
      c$rdp$last_size = c$resp$num_bytes_ip;
      schedule 10msecs { dump_bytes(id) };
      }


event signature_match(state: signature_state, msg: string, data: string)
	{
	state$conn$rdp = [$ts=network_time(), $uid=state$conn$uid, $id=state$conn$id];
    event dump_bytes(state$conn$id);
	}
