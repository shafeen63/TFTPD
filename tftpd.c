#include "tftpd.h"
#include "tftpd_task.c"
#include "tftpd_cmd.c"

void tftpd_init()
{
	initial_list.module_type = MODULE_TYPE_TFTPD;
	strcpy(initial_list.module_name, "tftptt");
	initial_list.version = 2;
	strcpy(initial_list.module_description, "RFC 1350 Implementation");
	initial_list.next = NULL;
	tftpd_register_cmds();
	register_module_version(&initial_list);
	init_tftp_sessions();
		
	interface_set_showrunning_service(MODULE_TYPE_TFTPD, tftp_show_running);
	
	TASK_ID task_id;
    task_id = sys_task_spawn("TFSR", 128, 0, 8192, tftpd_server, NULL, 0);
    if (task_id == (TASK_ID) SYS_ERROR)
    {
    	Print("Failed to create server task!!!\n");
	}
    return;
}


int32 tftp_show_running(DEVICE_ID diID)
{
	int rc = 0;
	
	if (diID == 0)
	{
		if(already_enable == 1)
		{
			vty_printf("tftp server enable\n");
			rc++;
			
			if(tftp_req_port != TFTP_REQ_PORT)
			{
				vty_printf("tftp server port %d\n", tftp_req_port);
				rc++;
			}
			
			if(timeout != RECV_TIMEOUT || retry != RECV_RETRIES)
			{
				vty_printf("tftp server retransmit %d %d\n", timeout, retry);
			 	rc++;
			}
		}
		
		if (rc)
			return INTERFACE_GLOBAL_SUCCESS;
		else
			return INTERFACE_DEVICE_ERROR_EMPTYCONFIGURATION;
	}
	
	return INTERFACE_GLOBAL_SUCCESS;
}


int parse_block_size(char *packet, int packet_len)
{
    int position = 2;
    while (position < packet_len && packet[position] != '\0')
	{
        position++;
    }
    position++;

    while (position < packet_len && packet[position] != '\0')
	{
        position++;
    }
    position++;

    if (position < packet_len)
	{
        while (position < packet_len)
		{
            char *option = packet + position;

            if (strcmp(option, "blksize") == 0)
			{
                char *value_start = option + strlen("blksize") + 1;
                int block_size = atoi(value_start);
                if(block_size == 512)
                {
                	return -1;
				}
				else if(block_size < 8 || block_size > 65464)
				{
					return -1;
				}
				else
				{
					return block_size;	
				}
                
            }

            position += strlen(option) + 1;
        }
    }
    return -1;
}


void reverse(char str[], int length)
{
	int start = 0;
	int end = length - 1;
	while (start < end)
	{
		char temp = str[start];
		str[start] = str[end];
		str[end] = temp;
		end--;
		start++;
	}
}

char* itoa(int num, char* str, int base)
{
	int i = 0;
	bool is_negative = false;

	if (num == 0)
	{
		str[i++] = '0';
		str[i] = '\0';
		return str;
	}

	if (num < 0 && base == 10)
	{
		is_negative = true;
		num = -num;
	}


	while (num != 0)
	{
		int rem = num % base;
		str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
		num = num / base;
	}

	if (is_negative)
		str[i++] = '-';

	str[i] = '\0'; 

	reverse(str, i);

	return str;
}


void init_tftp_sessions()
{
    memset(tftp_session, 0, sizeof(tftp_session));
}

int get_free_session()
{
	int i;
    for (i = 0; i < MAX_TFTP_SESSIONS; i++)
	{
        if (!tftp_session[i].active)
		{
            return i;
        }
    }
    return -1;
}

void close_session(int index)
{
    if (index >= 0 && index < MAX_TFTP_SESSIONS && tftp_session[index].active)
	{
		if(read_count > 0)
		{
			read_count--;	
		}

		if(write_mode == 1)
		{
			write_mode = 0;
		}

		memset(&tftp_session[index], 0, sizeof(tftp_session[index]));
	}
}

uint32 read_block_from_file(int index, int block_size, int offset, char *read_buf)
{
	uint32 read;
	int offset_seek = offset * block_size;
	FCB_POINT *file_p;
	while(1)
	{
		if(FILE_NOERROR == enter_filesys(OPEN_READ))
			break;
		else
			sys_task_delay(5);
	}
	
	file_p = file_open(tftp_session[index].filename, "r", NULL);

	if(file_p == NULL)
	{
		syslog(LOG_WARNING, "TFTP: %d- Failed to open file.\n", LOG_WARNING);
		exit_filesys(OPEN_READ);
		return -1;
	}
	
    file_seek(file_p, offset_seek, FROM_HEAD);

	read = file_read(file_p, read_buf, block_size);
    file_close(file_p);
	exit_filesys(OPEN_READ);
    return read;
}

void tftp_read_req(int index)
{
	TIMER_USER_DATA timer_ud;
	int rv;
	MSG_Q_ID msgq_rr;
	demo_msg_t msg_rr;	
	int sock_fd_rr = -1;
	unsigned long timer_id;
	struct soaddr_in serv_addr, client_address;
	char recv_buf[MAX_BLOCK_SIZE];
	char read_buf[MAX_BLOCK_SIZE];
	char error_buf[MAX_BLOCK_SIZE];
	char data_buf[MAX_BLOCK_SIZE];
	char oack_buf[MAX_BLOCK_SIZE];
	char option[MAX_ERROR_MESSAGE_SIZE];
	char option_value[MAX_ERROR_MESSAGE_SIZE];
	char error_msg_string[MAX_ERROR_MESSAGE_SIZE];
	int read;
	uint32 type, error_code, current_time;
	int block_number = 1;
	int retry_count  = 0;
	int offset = 0;
	int read_size;
	int send_size = 0;
	int buffer_offset = 0;
	int zero_block_flag = 0;
	FCB_POINT *file_p = NULL;
	int client_len = sizeof(client_address);
	int block_size = tftp_session[index].block_size;
	read_size = MAX_BLOCK_SIZE / block_size;
	
	msgq_rr = sys_msgq_create(256, Q_OP_FIFO);
	if (msgq_rr == NULL) 
	{
		syslog(LOG_WARNING, "TFTP: %d- Failed to crate messag equeue.\n", LOG_WARNING);
		sys_msgq_delete(msgq_rr);
		close_session(index);
		return;
	}

	sock_fd_rr = so_socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd_rr < 0)
	{
        syslog(LOG_WARNING, "TFTP: %d- Failed to create socket.\n", LOG_WARNING);
        so_close(sock_fd_rr);
		sys_msgq_delete(msgq_rr);
		close_session(index);
        return;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = 0;

	rv = so_bind(sock_fd_rr, (struct soaddr *)&serv_addr, sizeof(serv_addr));
    if (rv < 0)
	{
        syslog(LOG_WARNING, "TFTP: %d- Failed to bind socket.\n", LOG_WARNING);
        so_close(sock_fd_rr);
		sys_msgq_delete(msgq_rr);
		close_session(index);
        return;
    }

	rv = socket_register(sock_fd_rr, (ULONG)msgq_rr, 0);
    if (rv != 0)
	{
        syslog(LOG_WARNING, "TFTP: %d- Failed to register socket.\n", LOG_WARNING);
        so_close(sock_fd_rr);
		sys_msgq_delete(msgq_rr);
		close_session(index);
        return;
    }

	timer_ud.msg.qid = msgq_rr;
	timer_ud.msg.msg_buf[0] = MSG_TYPE_TIMER;
	sys_add_timer(TIMER_LOOP | TIMER_MSG_METHOD, &timer_ud, &timer_id);
	
	tftp_data *data_a = (tftp_data *)data_buf;
	tftp_error *error_a = (tftp_error *)error_buf;
	
	if(IsFileExist(tftp_session[index].filename) == 0)
	{
		syslog(LOG_WARNING, "TFTP: %d- File not found.\n", LOG_WARNING);
	    error_a->opcode = htons(TFTP_PKT_ERROR);
	    error_a->error_code = htons(ERR_FILE_NOT_FOUND);
	    strcpy(error_a->error_string, "File not found!!!");
		rv = so_sendto(sock_fd_rr, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
		sys_delete_timer(timer_id);
		so_close(sock_fd_rr);
		sys_msgq_delete(msgq_rr);
		close_session(index);
		return;	
	}
	current_time = tickGet();
	if(tftp_session[index].option_flag == 1)
	{
		tftp_oack *oack_a = (tftp_oack *)oack_buf;
	    oack_a->opcode = htons(TFTP_PKT_OACK);
	    strcpy(option, "blksize");
	    itoa(tftp_session[index].block_size, option_value, 10);
	    memcpy(oack_a->option_string, option, strlen(option) + 1);
	    memcpy(oack_a->option_string + strlen(option) + 1, option_value, strlen(option_value) + 1);
		rv = so_sendto(sock_fd_rr, oack_buf,  2 + strlen(option) + 1 + strlen(option_value) + 1, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
	    sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);  
	}
	
	else
	{
		memset(read_buf, 0, sizeof(read_buf));
		
		read = read_block_from_file(index, block_size, offset, read_buf);
		if(read < 0)
		{
			syslog(LOG_WARNING, "TFTP: %d- Failed to read file.\n", LOG_WARNING);
			if(sys_timer_run(timer_id))
			{
				sys_stop_timer(timer_id);
			}
			sys_delete_timer(timer_id);
			so_close(sock_fd_rr);
			sys_msgq_delete(msgq_rr);
			close_session(index);
			return;
		}
		offset++;
		data_a->opcode = htons(TFTP_PKT_DATA);
		data_a->block_number = htons(block_number);
		send_size = (read - buffer_offset > tftp_session[index].block_size)? tftp_session[index].block_size: read - buffer_offset;
		memcpy(data_a->data_block, read_buf + buffer_offset, send_size);
		
		rv = so_sendto(sock_fd_rr, data_buf, 4 + send_size, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
		sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
		
		if(send_size < tftp_session[index].block_size)
		{
			if(sys_timer_run(timer_id))
			{
				sys_stop_timer(timer_id);
			}
			sys_delete_timer(timer_id);
			so_close(sock_fd_rr);
			sys_msgq_delete(msgq_rr);
			close_session(index);
			return;
		}
	}
	
	while(1)
	{
		memset(&msg_rr, 0, sizeof(msg_rr));
		rv = sys_msgq_receive(msgq_rr, (unsigned long *) &msg_rr, SYS_WAIT_FOREVER);
		if (rv != SYS_OK)
		{
			continue;	
		}
		
		switch (msg_rr.msg_type)
		{
			case SOCKET_DATARCVD:
				memset(recv_buf, 0, sizeof(recv_buf));
				
				rv = so_recvfrom(sock_fd_rr, recv_buf, sizeof(recv_buf) , 0, (struct soaddr *)&client_address, &client_len);

				if(ntohs(client_address.sin_port) != ntohs(tftp_session[index].client_address_t.sin_port))
				{
					error_a->opcode = htons(TFTP_PKT_ERROR);
				    error_a->error_code = htons(ERR_ID);
				    strcpy(error_a->error_string, "Wrong TiD!!!");
					rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&client_address, client_len);
					continue;
				}
				
				type = ntohs(*(uint16 *)recv_buf);
				
				if(type == TFTP_PKT_ACK)
				{
					tftp_ack *ack_a = (tftp_ack *)recv_buf;
					
					if(ntohs(ack_a->block_number) == 0)
					{
						zero_block_flag = 1;
						if(sys_timer_run(timer_id))
						{
							sys_stop_timer(timer_id);
						}
						
						memset(read_buf, 0, sizeof(read_buf));
		
						read = read_block_from_file(index, block_size * read_size, offset, read_buf);
						if(read < 0)
						{
							syslog(LOG_WARNING, "TFTP: %d- Failed to read file.\n", LOG_WARNING);
							if(sys_timer_run(timer_id))
							{
								sys_stop_timer(timer_id);
							}
							sys_delete_timer(timer_id);
							so_close(sock_fd_rr);
							sys_msgq_delete(msgq_rr);
							close_session(index);
							return;
						}
						offset++;
						data_a->opcode = htons(TFTP_PKT_DATA);
						data_a->block_number = htons(block_number);
						send_size = (read - buffer_offset > tftp_session[index].block_size)? tftp_session[index].block_size: read - buffer_offset;
						memcpy(data_a->data_block, read_buf + buffer_offset, send_size);
						
						rv = so_sendto(sock_fd_rr, data_buf, 4 + send_size, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
						sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
						
						if(send_size < tftp_session[index].block_size)
						{
							if(sys_timer_run(timer_id))
							{
								sys_stop_timer(timer_id);
							}
							sys_delete_timer(timer_id);
							so_close(sock_fd_rr);
							sys_msgq_delete(msgq_rr);
							close_session(index);
							return;
						}
					}

					else if(ntohs(ack_a->block_number) != block_number)
					{
						continue;
					}
					
					else
					{
						buffer_offset += send_size;
						block_number++;
						retry_count = 0;
						sys_stop_timer(timer_id);
						
						if (buffer_offset >= read)
						{
							buffer_offset = 0;
							memset(read_buf, 0, sizeof(read_buf));
						
							read = read_block_from_file(index, block_size * read_size, offset, read_buf);
							if(read < 0)
							{
								if(sys_timer_run(timer_id))
								{
									sys_stop_timer(timer_id);
								}
								sys_delete_timer(timer_id);
								so_close(sock_fd_rr);
								sys_msgq_delete(msgq_rr);
								close_session(index);
								return;
							}
							offset++;
							data_a->opcode = htons(TFTP_PKT_DATA);
							data_a->block_number = htons(block_number);
							send_size = (read - buffer_offset > tftp_session[index].block_size)? tftp_session[index].block_size: read - buffer_offset;
							memcpy(data_a->data_block, read_buf + buffer_offset, send_size);
	
							rv = so_sendto(sock_fd_rr, data_buf, 4 + send_size, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
							sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
							
							if(send_size < tftp_session[index].block_size)
							{
								if(sys_timer_run(timer_id))
								{
									sys_stop_timer(timer_id);
								}
								sys_delete_timer(timer_id);
								so_close(sock_fd_rr);
								sys_msgq_delete(msgq_rr);
								close_session(index);
								return;
							}	
						}
						
						else
						{
							data_a->opcode = htons(TFTP_PKT_DATA);
							data_a->block_number = htons(block_number);
							send_size = (read - buffer_offset > tftp_session[index].block_size)? tftp_session[index].block_size: read - buffer_offset;
							memcpy(data_a->data_block, read_buf + buffer_offset, send_size);

							rv = so_sendto(sock_fd_rr, data_buf, 4 + send_size, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
							sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
						
							if(send_size < tftp_session[index].block_size)
							{
								if(sys_timer_run(timer_id))
								{
									sys_stop_timer(timer_id);
								}
								sys_delete_timer(timer_id);
								so_close(sock_fd_rr);
								sys_msgq_delete(msgq_rr);
								close_session(index);
								return;
							}	
						}
						
					}
					
					
					if(send_size < tftp_session[index].block_size)
					{
						if(sys_timer_run(timer_id))
						{
							sys_stop_timer(timer_id);
						}
						sys_delete_timer(timer_id);
						so_close(sock_fd_rr);
						sys_msgq_delete(msgq_rr);
						close_session(index);
						return;
					}
			
				}
				
				else if(type == TFTP_PKT_ERROR)
				{
					tftp_error *error_a = (tftp_error *)recv_buf;
					error_code = error_a->error_code;
				    strcpy(error_msg_string, error_a->error_string);
				    if(sys_timer_run(timer_id))
					{
						sys_stop_timer(timer_id);
					}
				    sys_delete_timer(timer_id);
					so_close(sock_fd_rr);
					sys_msgq_delete(msgq_rr);
					close_session(index);
					return;
				}
				
				else
				{
					error_a->opcode = htons(TFTP_PKT_ERROR);
				    error_a->error_code = htons(ERR_OP);
				    strcpy(error_a->error_string, "Wrong Opcode!!!");
					rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
					if(sys_timer_run(timer_id))
					{
						sys_stop_timer(timer_id);
					}
					sys_delete_timer(timer_id);
					so_close(sock_fd_rr);
					sys_msgq_delete(msgq_rr);
					close_session(index);
					return;
				} 
				break;
			
			case MSG_TYPE_TIMER:
				retry_count++;
				if(retry_count < retry)
				{
					if(tftp_session[index].option_flag == 1 && zero_block_flag == 0)
					{
						rv = so_sendto(sock_fd_rr, oack_buf,  2 + strlen(option) + 1 + strlen(option_value) + 1, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
					}
					
					else
					{
						rv = so_sendto(sock_fd_rr, data_buf, 4 + send_size, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
					}
					
				}
				else
				{
					if(sys_timer_run(timer_id))
					{
						sys_stop_timer(timer_id);
					}
					sys_delete_timer(timer_id);
					so_close(sock_fd_rr);
					sys_msgq_delete(msgq_rr);
					close_session(index);
					return ;
				}
				
				break;
				
			default:
				break;
		}
		if(tickGet() - current_time >= TIME_INTERVAL)
		{
			sys_task_delay(1);
		}
		current_time = tickGet();
	}
	so_close(sock_fd_rr);
}

void tftp_write_req(int index)
{
    TIMER_USER_DATA timer_ud;
	int rv;
	MSG_Q_ID msgq_wr;
	demo_msg_t msg_wr;	
	int sock_fd_wr = -1;
	uint32 type, error_code, current_time;
	uint16 received_block;
	unsigned long timer_id;
	struct soaddr_in serv_addr, client_address;
	char pkt_buf[MAX_BLOCK_SIZE];
	char ack_buf[MAX_BLOCK_SIZE];
	char data_buf[MAX_BLOCK_SIZE];
	char error_buf[MAX_BLOCK_SIZE];
	char recv_buf[MAX_BLOCK_SIZE];
	char oack_buf[MAX_BLOCK_SIZE];
	char option[MAX_BLOCK_SIZE];
	char option_value[MAX_BLOCK_SIZE];
	char error_msg_string[MAX_ERROR_MESSAGE_SIZE];
	
	int block_number = 0;
	int  last_received_block;
	int retry_count  = 0;
	int last_block;
	int oack_flag = 0;
	
	FCB_POINT *file_p = NULL;
	int client_len = sizeof(client_address);
	
	
	msgq_wr = sys_msgq_create(256, Q_OP_FIFO);
	if (msgq_wr == NULL) 
	{
		syslog(LOG_WARNING, "TFTP: %d- Failed to crate messag equeue.\n", LOG_WARNING);
		sys_msgq_delete(msgq_wr);
		close_session(index);
		return;
	}

	sock_fd_wr = so_socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd_wr < 0)
	{
        syslog(LOG_WARNING, "TFTP: %d- Failed to create socket.\n", LOG_WARNING);
        so_close(sock_fd_wr);
		sys_msgq_delete(msgq_wr);
		close_session(index);
        return;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = 0;

	rv = so_bind(sock_fd_wr, (struct soaddr *)&serv_addr, sizeof(serv_addr));
    if (rv < 0)
	{
        syslog(LOG_WARNING, "TFTP: %d- Failed to bind socket.\n", LOG_WARNING);
        so_close(sock_fd_wr);
		sys_msgq_delete(msgq_wr);
		close_session(index);
        return;
    }

	rv = socket_register(sock_fd_wr, (ULONG)msgq_wr, 0);
    if (rv != 0)
	{
        syslog(LOG_WARNING, "TFTP: %d- Failed to register socket.\n", LOG_WARNING);
        so_close(sock_fd_wr);
		sys_msgq_delete(msgq_wr);
		close_session(index);
        return;
    }

	timer_ud.msg.qid = msgq_wr;
	timer_ud.msg.msg_buf[0] = MSG_TYPE_TIMER;
	sys_add_timer(TIMER_LOOP | TIMER_MSG_METHOD, &timer_ud, &timer_id);
	
	rv = enter_filesys(OPEN_WRITE);
	if(rv != 0)
	{
		so_close(sock_fd_wr);
		sys_msgq_delete(msgq_wr);
		close_session(index);
		return;
	}
	
	tftp_error *error_a = (tftp_error *)error_buf;
	
	if(IsFileExist(tftp_session[index].filename) == 1)
	{
		syslog(LOG_WARNING, "TFTP: %d- File already exists.\n", LOG_WARNING);
	    error_a->opcode = htons(TFTP_PKT_ERROR);
	    error_a->error_code = htons(ERR_EXIST);
	    strcpy(error_a->error_string, "File already exists!!!");
		rv = so_sendto(sock_fd_wr, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
		exit_filesys(OPEN_WRITE);
		sys_delete_timer(timer_id);
		so_close(sock_fd_wr);
		sys_msgq_delete(msgq_wr);
		close_session(index);
		return;	
	}
	
	file_p = file_open(tftp_session[index].filename, "w", NULL);
	if(file_p == NULL)
	{
		syslog(LOG_WARNING, "TFTP: %d- Failed to open file.\n", LOG_WARNING);
	    error_a->opcode = htons(TFTP_PKT_ERROR);
	    error_a->error_code = htons(ERR_FILE_NOT_FOUND);
	    strcpy(error_a->error_string, "File Not Found!!!");
		rv = so_sendto(sock_fd_wr, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
		file_close(file_p);
		exit_filesys(OPEN_WRITE);
		sys_delete_timer(timer_id);
		so_close(sock_fd_wr);
		sys_msgq_delete(msgq_wr);
		close_session(index);
		return;
	}
	
	tftp_ack *ack_a = (tftp_ack *)ack_buf;
	
	if(tftp_session[index].option_flag == 0)
	{
	    ack_a->opcode = htons(TFTP_PKT_ACK);
	    ack_a->block_number = htons(block_number);
		rv = so_sendto(sock_fd_wr, ack_buf, 4, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
	    sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	}
	
	else
	{
		tftp_oack *oack_a = (tftp_oack *)oack_buf;
	    oack_a->opcode = htons(TFTP_PKT_OACK);
	    strcpy(option, "blksize");
	    itoa(tftp_session[index].block_size, option_value, 10);
	    memcpy(oack_a->option_string, option, strlen(option) + 1);
	    memcpy(oack_a->option_string + strlen(option) + 1, option_value, strlen(option_value) + 1);
		rv = so_sendto(sock_fd_wr, oack_buf,  2 + strlen(option) + 1 + strlen(option_value) + 1, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
		oack_flag = 1;
	    sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	}
    
    while (1)
	{
        memset(data_buf, 0, sizeof(data_buf));
		memset(pkt_buf, 0, sizeof(pkt_buf));
		
        rv = sys_msgq_receive(msgq_wr, (unsigned long *)&msg_wr, SYS_WAIT_FOREVER);
        if (rv != SYS_OK)
		{
            continue;
        }

        switch (msg_wr.msg_type)
		{
            case SOCKET_DATARCVD:
                rv = so_recvfrom(sock_fd_wr, recv_buf, sizeof(recv_buf), 0, (struct soaddr *)&client_address, &client_len);
                if (rv < 0)
				{
                    break;
                }
                type = ntohs(*(uint16 *)recv_buf);
                
                if(type == TFTP_PKT_DATA)
                {
                	if(tftp_session[index].option_flag == 1)
                	{
                		oack_flag = 0;
					}
					
                	sys_stop_timer(timer_id);
                	tftp_data *data_a = (tftp_data *)recv_buf;
	               
	                received_block = ntohs(data_a->block_number);
	                memcpy(pkt_buf, data_a->data_block, rv - 4);
			
	                if (received_block == block_number + 1)
					{
	                    file_write(file_p, pkt_buf, rv - 4);
						last_block = (rv < tftp_session[index].block_size) ? 1: 0;
						
	                    block_number = received_block;
						memset(ack_buf, 0, sizeof(ack_buf));
	                    ack_a->opcode = htons(TFTP_PKT_ACK);
				        ack_a->block_number = htons(block_number);
					    rv = so_sendto(sock_fd_wr, ack_buf, 4, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
				    	
						sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	                    retry_count = 0; 
	                    last_received_block = received_block;
	                    
	                    if(last_block)
	                    {
							file_close(file_p);
							exit_filesys(OPEN_WRITE);
							if(sys_timer_run(timer_id))
							{
								sys_stop_timer(timer_id);
							}
							sys_delete_timer(timer_id);
							so_close(sock_fd_wr);
							sys_msgq_delete(msgq_wr);
							close_session(index);
	                    	return;
						}
					}
					
					else if (received_block == last_received_block)
					{
						retry_count++;
	                    if(retry_count > RECV_RETRIES)
						{
	                       	file_close(file_p);
							exit_filesys(OPEN_WRITE);
							if(sys_timer_run(timer_id))
							{
								sys_stop_timer(timer_id);
							}
							sys_delete_timer(timer_id);
							so_close(sock_fd_wr);
							sys_msgq_delete(msgq_wr);
							close_session(index);
	                        return;
	                    }
	                    	
						memset(ack_buf, 0, sizeof(ack_buf));
	                    ack_a->opcode = htons(TFTP_PKT_ACK);
				        ack_a->block_number = htons(received_block);
					    rv = so_sendto(sock_fd_wr, ack_buf, 4, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
				        sys_start_timer(timer_id, TIMER_RESOLUTION_S | timeout);
	                }
				}
				
                else if(type == TFTP_PKT_ERROR)
                {
                	tftp_error *error_a = (tftp_error *)recv_buf;
					error_code = error_a->error_code;
				    strcpy(error_msg_string, error_a->error_string);
				    file_close(file_p);
					exit_filesys(OPEN_WRITE);
					if(sys_timer_run(timer_id))
					{
						sys_stop_timer(timer_id);
					}
					sys_delete_timer(timer_id);
					so_close(sock_fd_wr);
					sys_msgq_delete(msgq_wr);
					close_session(index);
					return;
				}
				
                else
                {
                	error_a->opcode = htons(TFTP_PKT_ERROR);
				    error_a->error_code = htons(ERR_OP);
				    strcpy(error_a->error_string, "Wrong Opcode!!!");
					rv = so_sendto(sock_fd, error_buf, sizeof(*error_a) + sizeof(tftp_error), 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
					file_close(file_p);
					exit_filesys(OPEN_WRITE);
					if(sys_timer_run(timer_id))
					{
						sys_stop_timer(timer_id);
					}
					sys_delete_timer(timer_id);
					so_close(sock_fd_wr);
					sys_msgq_delete(msgq_wr);
					close_session(index);
					break;	
				}
                
                break;
			
			case MSG_TYPE_TIMER:
				retry_count++;
                if(retry_count > retry)
				{
                    file_close(file_p);
					exit_filesys(OPEN_WRITE);
					if(sys_timer_run(timer_id))
					{
						sys_stop_timer(timer_id);
					}
					sys_delete_timer(timer_id);
					so_close(sock_fd_wr);
					sys_msgq_delete(msgq_wr);
					close_session(index);
                    return;
                }
                else if(tftp_session[index].option_flag == 1 && oack_flag == 1)
                {
                	rv = so_sendto(sock_fd_wr, oack_buf,  2 + strlen(option) + 1 + strlen(option_value) + 1, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
                	break;
				}
				else
				{
					memset(ack_buf, 0, sizeof(ack_buf));
	                ack_a->opcode = htons(TFTP_PKT_ACK);
			        ack_a->block_number = htons(received_block);
				    rv = so_sendto(sock_fd_wr, ack_buf, 4, 0, (struct soaddr *)&tftp_session[index].client_address_t, tftp_session[index].client_address_t_len);
					break;
				}
                break;
			
            default:
                break;
        }
        if(tickGet() - current_time >= TIME_INTERVAL)
        {
        	sys_task_delay(1);
		}
		current_time = tickGet();
        
    }
    so_close(sock_fd_wr);
}


