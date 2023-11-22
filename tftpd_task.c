
void tftpd_server()
{
	TASK_ID task_id;
    struct soaddr_in server_address, client_addr;
	uint32 rv;
	
	demo_msg_t msg;
	char pkt_buf[MAX_BLOCK_SIZE];
	char error_buf[MAX_BLOCK_SIZE];
	int len, pkt_buf_len, negotiated_size, block_size;
	len = sizeof(client_addr);
	pkt_buf_len = sizeof(pkt_buf);
	
	tftp_req *req_a = (tftp_req *)pkt_buf;
	tftp_error *error_a = (tftp_error *)error_buf;
	msgq_id = sys_msgq_create(256, Q_OP_FIFO);
	if (msgq_id == NULL)
	{
		syslog(LOG_ERR, "TFTP: %d- Failed to create server message queue.\n", LOG_ERR);
		return;
	}
	
    sock_fd = so_socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
	{
        syslog(LOG_ERR, "TFTP: %d- Failed to create server socket.\n", LOG_ERR);
        return;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(tftp_req_port);

	rv = so_bind(sock_fd, (struct soaddr *)&server_address, sizeof(server_address));
    if (rv < 0)
	{
        syslog(LOG_ERR, "TFTP: %d- Failed to bind server socket.\n", LOG_ERR);
        return;
    }
    
	rv = socket_register(sock_fd, (ULONG)msgq_id, 0);
    if (rv != 0)
	{
        syslog(LOG_ERR, "TFTP: %d- Failed to register server socket.\n", LOG_ERR);
        return;
    }
    
	while(1)
	{
		rv = sys_msgq_receive(msgq_id, (unsigned long *)&msg, SYS_WAIT_FOREVER);
		if (rv != SYS_OK)
		{
			continue;
		}
		
		switch (msg.msg_type)
		{
			case MSG_TFTP_DISABLE:
				if(already_enable == 0)
				{
			
				}
				else
				{
					already_enable = 0;
				    socket_unregister(sock_fd);
				    so_close(sock_fd);	
				}
				 
				break;
				
			case MSG_TFTP_ENABLE:
				if(already_enable == 1)
				{
				
				}
				else
				{
					already_enable = 1;
					
					sock_fd = so_socket(AF_INET, SOCK_DGRAM, 0);
				    if (sock_fd < 0)
					{
				        syslog(LOG_ERR, "TFTP: %d- Failed to create server socket.\n", LOG_ERR);
				        return;
				    }
				
				    memset(&server_address, 0, sizeof(server_address));
				    server_address.sin_family = AF_INET;
				    server_address.sin_port = htons(tftp_req_port);
				
					rv = so_bind(sock_fd, (struct soaddr *)&server_address, sizeof(server_address));
				    if (rv < 0)
					{
				        syslog(LOG_ERR, "TFTP: %d- Failed to bind server socket.\n", LOG_ERR);
				        return;
				    }
				}
				
				break;
				
			case MSG_PORT_SET:
				tftp_req_port = msg.count;
				
				socket_unregister(sock_fd);
				so_close(sock_fd);
				sock_fd = so_socket(AF_INET, SOCK_DGRAM, 0);
			    if (sock_fd < 0)
				{
			        syslog(LOG_ERR, "TFTP: %d- Failed to create server socket.\n", LOG_ERR);
			        return;
			    }
			
			    memset(&server_address, 0, sizeof(server_address));
			    server_address.sin_family = AF_INET;
			    server_address.sin_port = htons(tftp_req_port);
			
				rv = so_bind(sock_fd, (struct soaddr *)&server_address, sizeof(server_address));
			    if (rv < 0)
				{
			        syslog(LOG_ERR, "TFTP: %d- Failed to bind server socket.\n", LOG_ERR);
			        return;
			    }
			    
				rv = socket_register(sock_fd, (ULONG)msgq_id, 0);
			    if (rv != 0)
				{
			        syslog(LOG_ERR, "TFTP: %d- Failed to register server socket.\n", LOG_ERR);
			        return;
			    }
				break;
			
			case MSG_PORT_DEFAULT:
				tftp_req_port = msg.count;
		
				socket_unregister(sock_fd);
				so_close(sock_fd);
				sock_fd = so_socket(AF_INET, SOCK_DGRAM, 0);
			    if (sock_fd < 0)
				{
			        syslog(LOG_ERR, "TFTP: %d- Failed to create server socket.\n", LOG_ERR);
			        return;
			    }
			
			    memset(&server_address, 0, sizeof(server_address));
			    server_address.sin_family = AF_INET;
			    server_address.sin_port = htons(tftp_req_port);
			
				rv = so_bind(sock_fd, (struct soaddr *)&server_address, sizeof(server_address));
			    if (rv < 0)
				{
			        syslog(LOG_ERR, "TFTP: %d- Failed to bind server socket.\n", LOG_ERR);
			        return;
			    }
			    
				rv = socket_register(sock_fd, (ULONG)msgq_id, 0);
			    if (rv != 0)
				{
			        syslog(LOG_ERR, "TFTP: %d- Failed to register server socket.\n", LOG_ERR);
			        return;
			    }
				break;
			
			case MSG_RETRNSMT_DEFAULT:
				timeout = msg.count;
				retry = msg.reserved1;
				break;
			
			case MSG_RETRNSMT_SET:
				timeout = msg.count;
				retry = msg.reserved1;
				break;
			
			case SOCKET_DATARCVD:

				rv = so_recvfrom(sock_fd, &pkt_buf, sizeof(pkt_buf), 0, (struct soaddr *)&client_addr, &len);
				if(rv <0)
				{
					so_close(sock_fd);
        			return;
				}

				if(ntohs(req_a->opcode) == TFTP_PKT_RRQ)
				{
					if(write_mode == 0)
					{
						int free_index = get_free_session();
						if(free_index < 0)
						{
							error_a->opcode = htons(TFTP_PKT_ERROR);
						    error_a->error_code = htons(ERR_NOSPACE);
						    strcpy(error_a->error_string, "Not enough space!!!");
							rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&client_addr, len);
							continue;
							
						}
					
						if(read_count < 3)
						{
							read_count++;
						}
						else
						{
							error_a->opcode = htons(TFTP_PKT_ERROR);
						    error_a->error_code = htons(ERR_NOSPACE);
						    strcpy(error_a->error_string, "Not enough space!!!");
							rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&client_addr, len);
							continue;	
						}
						
						if(strlen(req_a->filename) == 0 || strlen(req_a->filename) > 255)
						{
							error_a->opcode = htons(TFTP_PKT_ERROR);
						    error_a->error_code = htons(ERR_UNDEF);
						    strcpy(error_a->error_string, "File error!!!");
							rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&client_addr, len);
							continue;	
						}
						
						tftp_session[free_index].active = 1;
						strcpy(tftp_session[free_index].filename, req_a->filename);
						tftp_session[free_index].client_address_t = client_addr;
						tftp_session[free_index].client_address_t_len = len;
						tftp_session[free_index].session_id = free_index;
						tftp_session[free_index].opcode = req_a->opcode;
						negotiated_size = parse_block_size(pkt_buf, pkt_buf_len);
						if(negotiated_size == -1)
						{
							block_size = DEF_BLOCK_SIZE;
							tftp_session[free_index].option_flag = 0;
						}
						else
						{
							block_size = negotiated_size;
							tftp_session[free_index].option_flag = 1;
						}
						tftp_session[free_index].block_size = block_size;

						uint32 arr[4] = {0};
						arr[0] = free_index; 
					
						task_id = sys_task_spawn("TFRQ", 128, 0, 400192, tftp_read_req, arr, 0);
						if (task_id == (TASK_ID) SYS_ERROR)
						{
							syslog(LOG_ERR, "TFTP: %d- Failed to create RRQ Task.\n", LOG_ERR);
							return;
						}	
					}
					else
					{
						error_a->opcode = htons(TFTP_PKT_ERROR);
					    error_a->error_code = htons(ERR_ACCESS);
					    strcpy(error_a->error_string, "Access Not Granted!!!");
						rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&client_addr, len);
						continue;
					}
					
				}
				
				else if(ntohs(req_a->opcode) == TFTP_PKT_WRQ)
				{
					if(write_mode == 0 && read_count == 0)
					{
						int free_index = get_free_session();
						if(index < 0)
						{
							error_a->opcode = htons(TFTP_PKT_ERROR);
						    error_a->error_code = htons(ERR_NOSPACE);
						    strcpy(error_a->error_string, "Not enough space!!!");
							rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&client_addr, len);
							continue;
						}
						
						if(strlen(req_a->filename) == 0 || strlen(req_a->filename) > 255)
						{
							error_a->opcode = htons(TFTP_PKT_ERROR);
						    error_a->error_code = htons(ERR_UNDEF);
						    strcpy(error_a->error_string, "File error!!!");
							rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&client_addr, len);
							continue;	
						}
						
						write_mode = 1;
						tftp_session[free_index].active = 1;
						strcpy(tftp_session[free_index].filename, req_a->filename);
						tftp_session[free_index].client_address_t = client_addr;
						tftp_session[free_index].client_address_t_len = len;
						tftp_session[free_index].session_id = free_index;
						tftp_session[free_index].opcode = req_a->opcode;
						negotiated_size = parse_block_size(pkt_buf, pkt_buf_len);
						if(negotiated_size == -1)
						{
							block_size = DEF_BLOCK_SIZE;
							tftp_session[free_index].option_flag = 0;
							
						}
						else
						{
							block_size = negotiated_size;
							tftp_session[free_index].option_flag = 1;
						}
						tftp_session[free_index].block_size = block_size;
						
						uint32 arr[4] = {0};
						arr[0] = free_index;
						
					
						task_id = sys_task_spawn("TFRQ", 128, 0, 150192, tftp_write_req, arr, 0);
						if (task_id == (TASK_ID) SYS_ERROR)
						{
							syslog(LOG_ERR, "TFTP: %d- Failed to create WRQ Task.\n", LOG_ERR);
							return;
						}
					}
					else
					{
						error_a->opcode = htons(TFTP_PKT_ERROR);
					    error_a->error_code = htons(ERR_ACCESS);
					    strcpy(error_a->error_string, "Access Not Granted!!!");
						rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&client_addr, len);
						continue;
					}
				
				}
				
				else
				{
					error_a->opcode = htons(TFTP_PKT_ERROR);
				    error_a->error_code = htons(ERR_OP);
				    strcpy(error_a->error_string, "Wrong Opcode!!!");
					rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&client_addr, len);
					continue;
				}
				break;
					
			default:
				break;
		}
		
	}	
	
	so_close(sock_fd);
	return ;
}
