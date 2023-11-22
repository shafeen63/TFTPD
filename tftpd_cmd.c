static struct topcmds top_tftp_cmd[] = 
{
  { "tftp", cmdPref(PF_CMDNO, PF_CMDDEF, 0),
    IF_ANY, ~FG_GLOBAL, IF_NULL, FG_CONFIG, 
    cmd_conf_tftp, NULL, NULL, 0, 0,
    "tftp        -- TFTP configuration",
    "tftp        -- TFTP 配置命令",
    NULLCHAR, NULLCHAR
  },
  { NULLCHAR }
};

static struct cmds tftp_cmds[] = 
{
  { "server", MATCH_AMB, cmdPref(PF_CMDNO, PF_CMDDEF, 0), 0,
    cmd_conf_tftp_server, NULL, NULL, 2, 0, 
    "server        -- TFTP server configuration",
    "server        -- TFTP 客户端配置命令",
    NULLCHAR, NULLCHAR
  },

  { NULLCHAR }
};

struct cmds tftp_show_cmd[] = 
{
  { "tftp", MATCH_AMB, 0, 0, show_tftp, NULL, NULL, 0, 0,
    "tftp                 --TFTP",
    "tftp                 --TFTP",
    NULLCHAR, NULLCHAR
  },
  { NULLCHAR }
};

struct cmds tftp_show_sub_cmds[] = 
{
  { "server", MATCH_AMB, 0, 0, do_show_tftp_server, NULL, NULL, 0, 1,
    "server              --server",
    "server              --统计信息",
    NULLCHAR, NULLCHAR
  },
  { NULLCHAR }
};

static struct cmds tftp_server_cmds[] =
{
    { "enable", MATCH_AMB, cmdPref(PF_CMDNO, 0, 0), 0,
	    do_enable_tftp, NULL, NULL, 1, 1, 
	    "enable               -- enable TFTP server",
	    "enable               -- 启动TFTP客户端并连接服务器",
	    NULLCHAR, NULLCHAR
  	},
  
    { "port", MATCH_AMB, cmdPref(PF_CMDNO, PF_CMDDEF, 0), 0,
        do_set_tftp__port, NULL, NULL, 1, 2,
        "port           -- set TFTP server port",
        "port           -- 设置MQTT服务器端口",
    },
    
    { "retransmit", MATCH_AMB, cmdPref(PF_CMDNO, PF_CMDDEF, 0), 0,
        do_set_tftp__retransmit, NULL, NULL, 1, 3,
        "retransmit           -- set TFTP retransmit",
        "port           -- 设置MQTT服务器端口",
    },

  { NULLCHAR }
};

static int cmd_conf_tftp(int argc, char **argv, struct user *u)
{
	return subcmd(tftp_cmds, NULL, argc, argv, u);
}

static int cmd_conf_tftp_server(int argc, char **argv, struct user *u)
{
	return subcmd(tftp_server_cmds, NULL, argc, argv, u);
}

int show_tftp(int argc, char **argv, struct user *u)
{
	return subcmd(tftp_show_sub_cmds, NULL, argc, argv, u);
}

static int do_enable_tftp(int argc, char **argv, struct user *u)
{
	int rv;
	demo_msg_t msg;

	if(IsNoPref(u))
	{
		msg.msg_type = MSG_TFTP_DISABLE;
		rv = sys_msgq_send(msgq_id, (char *)&msg, Q_OP_NORMAL, SYS_NO_WAIT);	
	}
		
	else
	{
		msg.msg_type = MSG_TFTP_ENABLE;
		rv = sys_msgq_send(msgq_id, (char *)&msg, Q_OP_NORMAL, SYS_NO_WAIT);	
	}
	
	return 0;
}

static int do_set_tftp__port(int argc, char **argv, struct user *u)
{
	int error, rv;
	uint32 port;
	demo_msg_t msg;
	struct parameter param;
	
	memset(&param, 0,sizeof(struct parameter));
	param.type = ARG_INT;

	if(IsNoPref(u) || IsDefPref(u))
	{
		port = TFTP_REQ_PORT;
		msg.msg_type = MSG_PORT_DEFAULT;
		msg.count = port;
		rv = sys_msgq_send(msgq_id, (char *)&msg, Q_OP_NORMAL, SYS_NO_WAIT);
		
		return 0;
	}

	if ('?' == argv[1][0])
	{
		if (IsChinese(u))
			vty_output("  <0-65535>    -- tftp服务器端口\n");
		else
			vty_output("  <0-65535>    -- tftp server port number\n");
		
		return 0;
	}

	if ((error = getparameter(argc--, argv++, u, &param)))
		return error;

	port = param.value.v_int;

	if(port <= 65535 && port >= 0)
	{
		msg.msg_type = MSG_PORT_SET;
		msg.count = port;
		rv = sys_msgq_send(msgq_id, (char *)&msg, Q_OP_NORMAL, SYS_NO_WAIT);
	}
	
	else
		vty_output("server port out of range 0-65535, not set\n");
		
	return 0;
}

static int do_set_tftp__retransmit(int argc, char **argv, struct user *u)
{
	int error, rv;
	uint32 set_timeout, set_retry;
	demo_msg_t msg;
	struct parameter param;
	
	memset(&param, 0,sizeof(struct parameter));
	param.type = ARG_INT;

	if(IsNoPref(u) || IsDefPref(u))
	{
		set_timeout = RECV_TIMEOUT;
		set_retry = RECV_RETRIES;
		msg.msg_type = MSG_RETRNSMT_DEFAULT;
		msg.count = set_timeout;
		msg.reserved1 = set_retry;
		rv = sys_msgq_send(msgq_id, (char *)&msg, Q_OP_NORMAL, SYS_NO_WAIT);
		
		return 0;
	}
	
	if ('?' == argv[1][0])
	{
		if (IsChinese(u))
			vty_output("  <timeout> <retry>    -- tftp服务器端口\n");
		else
			vty_output("  <timeout> <retry>    -- tftp server timeout and retry count\n");
		
		return 0;
	}
	
	if (argc == 3 && '?' == argv[2][0])
	{
		if (IsChinese(u))
			vty_output("  <retry>    -- tftp服务器端口\n");
		else
			vty_output("  <retry>    -- tftp server retry count\n");
		
		return 0;
	}
	
	if(argc != 3)
		return 0;


	if ((error = getparameter(argc, argv, u, &param)))
		return error;

	set_timeout = atoi(argv[1]);
	set_retry = atoi(argv[2]);
	
	if((set_timeout <= 255 && set_timeout >= 1) && (set_retry <= 6 && set_retry >= 1) && (set_timeout * set_retry <= 255)) 
	{
		msg.msg_type = MSG_RETRNSMT_SET;
		msg.count = set_timeout;
		msg.reserved1 = set_retry;
		rv = sys_msgq_send(msgq_id, (char *)&msg, Q_OP_NORMAL, SYS_NO_WAIT);
	}
		
	else
		vty_output("server timeout out of range 1-255, not set or server retransmit out of range 1-6, not set  \n");
		
	return 0;
}

static int do_show_tftp_server(int argc, char **argv, struct user *u)
{
	int i, count;
	count = 0;
	vty_printf("tftp server configurations!\n");
	vty_printf("----------------------------------------------------------------------\n\n");
	if(already_enable == 1)
	{
		vty_printf("TFTP server : Enabled\n", tftp_req_port);
	}
	vty_printf("TFTP server port: %d\n", tftp_req_port);
	vty_printf("TFTP server timeout: %d\n", timeout);
	vty_printf("TFTP server retry: %d\n\n", retry);
	
	vty_printf("tftp session info!\n");
	vty_printf("----------------------------------------------------------------------\n\n");
	
	for(i = 0; i < MAX_TFTP_SESSIONS; i++)
	{
		if(tftp_session[i].active == 1)
		{
			vty_printf("TFTP server active session id: %d\n", i);
			
			if(tftp_session[i].opcode == TFTP_PKT_RRQ)
			{
				vty_printf("TFTP server operation: READ!\n");
			}
			if(tftp_session[i].opcode == TFTP_PKT_WRQ)
			{
				vty_printf("TFTP server operation: WRITE!\n");
			}
			vty_printf("TFTP server filename: %s\n\n", tftp_session[i].filename);
			count++;
		}
	}
	
	if(count == 0)
	{
		vty_printf("No session is active now!!!\n");
	}
	
	vty_printf_end(1);
	return 0;
}

void tftpd_register_cmds(void)
{
	registercmd(top_tftp_cmd);
	register_subcmd("show", 0, IF_NULL, FG_ENABLE, tftp_show_cmd);
	
	return;
}
