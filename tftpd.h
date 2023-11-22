#include <taskLib.h>
#include <semLib.h>
#include <string.h>
#include <libsys/vos/vos_task.h>
#include <libsys/vos/vos_msgq.h>
#include <ip/socket.h>
#include <ip/sockdefs.h>
#include <ip/errno.h>
#include <ip/msg.h>
#include <ip/inet.h>
#include <ip/in.h>
#include <ip/netdb.h>
#include <libfile/file_sys.h>
#include <time/time.h>
#include <libsys/timer.h>
#include <libsys/verctl.h>
#include <stdbool.h>
#include <stdio.h>
//#include "tftp_cmd.c"

#include <libcmd/cmdparse.h>
#include <libcmd/argparse.h>
#include <libcmd/cmderror.h>

/*message types*/
#define MSG_TYPE_MSG_Q         1
#define MSG_TYPE_TIMER         2
#define MSG_TFTP_DISABLE       3
#define MSG_TFTP_ENABLE        4
#define MSG_PORT_DEFAULT       5
#define MSG_PORT_SET           6
#define MSG_RETRNSMT_DEFAULT   7
#define MSG_RETRNSMT_SET       8

/* constants */
#define TFTP_REQ_PORT                     69
#define MAX_TFTP_SESSIONS                  3
#define MAX_FILE_NAME_LENGTH             256
#define MAX_MODE                          30
#define MAX_ERROR_MESSAGE_SIZE           128
#define DEF_BLOCK_SIZE                   512
#define MAX_BLOCK_SIZE                 64500
#define RECV_TIMEOUT                       3
#define RECV_RETRIES                       3
#define TIME_INTERVAL                     50


/* packet types */
#define TFTP_PKT_RRQ         1
#define TFTP_PKT_WRQ         2
#define TFTP_PKT_DATA        3
#define TFTP_PKT_ACK         4
#define TFTP_PKT_ERROR       5
#define TFTP_PKT_OACK        6

/* Error packet types */
#define ERR_UNDEF                     0 
#define ERR_FILE_NOT_FOUND            1 
#define ERR_ACCESS                    2
#define ERR_NOSPACE                   3
#define ERR_OP                        4 
#define ERR_ID                        5 
#define ERR_EXIST                     6 
#define ERR_USER                      7 
#define ERR_OPNEG                     8 

typedef struct
{
	uint16 opcode;
	char filename[0];
	char mode[0];
} __attribute__((packed)) tftp_req;

typedef struct
{
	uint16 opcode;
	uint16 block_number;
	char data_block[0];
} __attribute__((packed)) tftp_data;

typedef struct
{
	uint16 opcode;
	uint16 block_number;
} __attribute__((packed)) tftp_ack;

typedef struct
{
	unsigned long msg_type;
	unsigned long count;
	unsigned long reserved1;
	unsigned long reserved2;
}demo_msg_t;

typedef struct
{
    uint16 opcode;
    uint16 error_code;
    char error_string[0];
}__attribute__ ((packed)) tftp_error;

typedef struct
{
    uint16 opcode;
    char option_string[0];
}__attribute__ ((packed)) tftp_oack;

typedef struct
{
    int active;
    struct soaddr_in client_address_t;
    int client_address_t_len;
    char filename[MAX_FILE_NAME_LENGTH];
    uint16 opcode;
    uint16 block_number;
    uint32 block_size;
    int session_id;
    int option_flag;
}__attribute__ ((packed))tftp_session_t;



int sock_fd = -1;
MSG_Q_ID msgq_id;
int write_mode = 0;
int read_count = 0;
int already_enable = 1;
uint32 tftp_req_port = TFTP_REQ_PORT;
uint32 timeout = RECV_TIMEOUT;
uint32 retry = RECV_RETRIES; 

struct version_list initial_list;
tftp_session_t tftp_session[MAX_TFTP_SESSIONS];

extern unsigned long Print(char *format, ...);
void tftpd_server();
void tftp_read_req();
void tftp_write_req();
void init_tftp_sessions();
int get_free_session();
void close_session(int);
uint32 read_block_from_file(int, int, int, char *);
int parse_block_size(char *, int);
char* itoa(int , char * , int);
void reverse(char *, int);
int32 tftp_show_running(DEVICE_ID);

static int cmd_conf_tftp(int argc, char **argv, struct user *u);
static int cmd_conf_tftp_server(int argc, char **argv, struct user *u);
static int do_enable_tftp(int argc, char **argv, struct user *u);
static int do_set_tftp__port(int argc, char **argv, struct user *u);
static int do_set_tftp__retransmit(int argc, char **argv, struct user *u);
int show_tftp(int argc, char **argv, struct user *u);
static int do_show_tftp_server(int argc, char **argv, struct user *u);

