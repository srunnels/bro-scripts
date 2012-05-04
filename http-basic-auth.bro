module SRunnelsModule;

export {
  redef enum Notice::Type += {
    ## Generated if a site is detected using Basic Access Authentication
    HTTP::Basic_Auth_Server
  };
}

event http_header(c: connection, is_orig: bool, name: string, value: string) 
	{
	if (/AUTHORIZATION/ in name && /Basic/ in value)
		{
		local parts = split1(decode_base64(sub_bytes(value, 7, |value|)), /:/);
		if (|parts| == 2)
		  NOTICE([$note=HTTP::Basic_Auth_Server,
                  $msg="Server identified in which Basic Access Authentication is in use.",
	  			  $sub=fmt("username: %s password: %s", 
				  parts[1], 
				  HTTP::default_capture_password == F ? "Blocked" : parts[2]),
				  $action=Notice::ACTION_EMAIL,
				  $conn=c,
				  $identifier=cat(c$id$resp_h,c$id$resp_p),
				  $suppress_for=1day
				 ]);
		}
	}
