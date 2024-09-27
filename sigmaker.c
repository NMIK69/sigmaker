#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>

#define ARR_SIZE(arr) (sizeof(arr) / sizeof(*arr))

struct signature
{
	char *bytes;
	size_t idx;
	size_t size;
	size_t len;
	size_t offset;
};

struct instruction
{
	/* x86_64 max number of bytes for an instruction is 15. */
	/* 15 * 3, beacuse there is whitespace between every byte + one byte is
	 * two characters. + 1 for null terminator.*/
#define INST_SIZE ((15 * 3) + 1)
	char bytes[INST_SIZE];

	/* size should be more then enough */
	char mnemonic[32];
	char op1[64];
	char op2[64];

	struct instruction *next;
};

struct user_input
{
	char *file_path;
	char *target;
	int max_sig_len;
	int offset;
};

static long get_file_size(FILE *f);
static char *get_file_content(const char *path);

static char *get_location(const char *haystack, const char *needle);
static char *get_func_data(const char *fcont, const char *target);

static struct instruction *parse_line(char *line);
static struct instruction *get_instructions(char *func_data, size_t *nbytes);

static int is_call(char *op);
static int is_lea(char *op);
static int is_missing_bytes(struct instruction *inst);
static void append_inst_bytes(struct instruction *dst, struct instruction *src);
static int is_dynamic(struct instruction *inst);
static void sig_add_wildcard(struct signature *sig);
static void sig_add_byte(struct signature *sig, char *byte);
static void process_instruction(struct instruction *inst, struct signature *sig);

static struct signature make_signature(char *func_data, int max_len, int offset);
static void display_sig(struct signature *sig);

static struct user_input get_user_input(int argc, char **argv);

int main(int argc, char **argv)
{
	struct user_input uin = get_user_input(argc, argv);

	char *fcont = get_file_content(uin.file_path);
	char *func_data = get_func_data(fcont, uin.target);			
	free(fcont);

	struct signature sig = make_signature(func_data, uin.max_sig_len, uin.offset);
	display_sig(&sig);

	free(func_data);
	free(sig.bytes);

	return 0;
}

static struct user_input get_user_input(int argc, char **argv)
{
	struct user_input uin = {NULL, NULL, -1, 0};

	if(argc <= 2)
		goto usage_err;
	
	uin.file_path = argv[1];
	uin.target = argv[2];

	int opt;
	while((opt = getopt(argc, argv, "l:o:h")) != -1) {
		switch(opt) {
		case 'l':
			uin.max_sig_len = atoi(optarg);
			break;
		case 'o':
			uin.offset = atoi(optarg);		
			break;
		case 'h':
			goto usage_err;
			break;
		default:
			goto usage_err;
		}
	}

	return uin;

usage_err:
	fprintf(stderr, "Usage: \n\t%s [objdump file] [function name]\n"
		"\nOptions:\n"
		"\t[-l max signature length]\n"
		"\t[-o offset into the signature (in number of instructions)]\n", argv[0]);
	exit(EXIT_FAILURE);
}

static void pretty_print_sig(const char *bytes)
{
	size_t ws_count = 1;
	printf("\t\"");
	for(size_t i = 0; i < strlen(bytes); i++) {
		printf("%c", bytes[i]);

		if(bytes[i] == ' ' && ws_count++ % 18 == 0)
			printf("\"\n\t\"");
	}
	printf("\";");
}
static void display_sig(struct signature *sig)
{
	printf("[#] SIGNATURE: \n");
	pretty_print_sig(sig->bytes);
	printf("\n");
	printf("[#] LEN:       	    %zu\n", sig->len);
	printf("[#] OFFSET:         %zu\n", sig->offset);
}

static int is_call(char *op)
{
	if(strcmp(op, "call") == 0)
		return 1;
	
	return 0;
}

static int is_lea(char *op)
{
	if(strcmp(op, "lea") == 0)
		return 1;
	
	return 0;
}

static struct instruction *get_invalid_inst()
{
	struct instruction *inst = malloc(sizeof(*inst));
	if(inst == NULL)
		return NULL;

	strncpy(inst->mnemonic, "None", ARR_SIZE(inst->mnemonic));	
	strncpy(inst->op1, "None", ARR_SIZE(inst->op1));	
	strncpy(inst->op2, "None", ARR_SIZE(inst->op2));	
	inst->bytes[0] = '\0';
	inst->next = NULL;

	return inst;

}

static void trim_wspace(char *bytes)
{
	size_t len = strlen(bytes);
	int i = len;
	while(i >= 0 && isalnum(bytes[i]) == 0) {
		if(isspace(bytes[i]) || isblank(bytes[i]))
			bytes[i] = '\0';
		i -= 1;
	}
}

/* not my proudest work */
static struct instruction *parse_line(char *line)
{
	struct instruction *inst = get_invalid_inst();	
	assert(inst != NULL);

	/* throw away */
	char *tok = strtok(line, "\t");
	if(tok == NULL)
		return inst;

	char *bytes = strtok(NULL, "\t");
	if(bytes == NULL)
		return inst;

	trim_wspace(bytes);
	assert(bytes != NULL && strlen(bytes) <= ARR_SIZE(inst->bytes));
	strcpy(inst->bytes, bytes);

	char *mnemonic = strtok(NULL, " ");
	/* just bytes of the previous line */
	if(mnemonic == NULL)
		return inst;

	assert(strlen(mnemonic) <= ARR_SIZE(inst->mnemonic));
	strcpy(inst->mnemonic, mnemonic);

	char *op1 = strtok(NULL, ",");
	/* no first operand ? */
	if(op1 == NULL)
		return inst;
	
	assert(strlen(op1) <= ARR_SIZE(inst->op1));
	strcpy(inst->op1, op1);

	char *op2 = strtok(NULL, " \n");
	/* no second operand ? */
	if(op2 == NULL)
		return inst;

	assert(strlen(op2) <= ARR_SIZE(inst->op2));
	strcpy(inst->op2, op2);
	
	return inst;
}

static int is_missing_bytes(struct instruction *inst)
{
	if(strcmp(inst->mnemonic, "None") == 0)
		return 1;

	return 0;
}

static void append_inst_bytes(struct instruction *dst, struct instruction *src)
{
	size_t dst_blen = strlen(dst->bytes);	
	size_t src_blen = strlen(src->bytes);	
	size_t size = ARR_SIZE(dst->bytes);
	
	/* + 2 for one whitespace and nullterminator. */
	assert((dst_blen + src_blen + 2) < size);
	
	dst->bytes[dst_blen] = ' ';
	for(size_t i = 0; i < src_blen + 1; i++) {
		dst->bytes[dst_blen + 1 + i] = src->bytes[i];
	}
}

/* not my proudest work either. Who cares. */
static struct instruction *get_instructions(char *func_data, size_t *nbytes)
{
	struct instruction *cur = NULL;
	struct instruction *head = NULL;
	
	/* consume function name */
	char *line = strtok(func_data, "\n");
	assert(line != NULL);
	
	/* get actual first line */
	line = strtok(NULL, "\n");
	
	while(line != NULL) {

		/* "process_instruction()" calls strtok aswell, so we save where we
		 * need to continue with strtok to get the next line. */
		char *cont = (char *)((uintptr_t)line + 1 + (uintptr_t)strlen(line));

		struct instruction *tmp = parse_line(line);
		/* track the number of bytes the entire function is made of */
		*nbytes += strlen(tmp->bytes) + 1; 


		/* for large instructions, some bytes will be written on the
		 * next line. Append the missing bytes if that is the case. */
		if(is_missing_bytes(tmp) == 1) {
			assert(head != NULL && cur != NULL);
			append_inst_bytes(cur, tmp);		
			free(tmp);
		}
		/* if not, then we have a new instrcution. */
		else {
			if(head == NULL) {
				head = tmp;
				cur = tmp;
			}
			else {
				cur->next = tmp;
				cur = cur->next;
			}
		}

		line = strtok(cont, "\n");
	}

	return head;
}


static int is_dynamic(struct instruction *inst)
{
	if((is_call(inst->mnemonic) == 1) ||
	   (is_lea(inst->mnemonic) == 1)) { 
		
		return 1;
	}

	return 0;
}


static void sig_add_wildcard(struct signature *sig)
{
	sig->bytes[sig->idx++] = '?';
	sig->bytes[sig->idx++] = '?';
	sig->bytes[sig->idx++] = ' ';
}


static void sig_add_byte(struct signature *sig, char *byte)
{
	assert(strlen(byte) == 2);	

	sig->bytes[sig->idx++] = byte[0];
	sig->bytes[sig->idx++] = byte[1];
	sig->bytes[sig->idx++] = ' ';
}


static void process_instruction(struct instruction *inst, struct signature *sig)
{
	/* wildcards:
		- lea with [rip + 0x0]
		- call with 00 00 00 00 
	*/
	char buf[INST_SIZE];
	
	assert(sig->idx < sig->size);

	size_t len = strlen(inst->bytes);
	assert(sig->idx + len < sig->size);

	strncpy(buf, inst->bytes, ARR_SIZE(buf));


	char *byte = strtok(buf, " ");
	
	while(byte != NULL) {
		if(strlen(byte) != 2)
			return;

		if(is_dynamic(inst) == 1) {
			if(byte[0] == '0' && byte[1] == '0') {
				sig_add_wildcard(sig);	
			}
			else {
				sig_add_byte(sig, byte);
			}
		}
		else {
			sig_add_byte(sig, byte);
		}

		sig->len += 1;
	
		byte = strtok(NULL, " ");
	}
}

static struct signature make_signature(char *func_data, int max_len, int offset)
{
	size_t nbytes = 0;
	struct instruction *inst = get_instructions(func_data, &nbytes);

	struct signature sig = {0};
	sig.bytes = malloc(sizeof(*sig.bytes) * nbytes);
	assert(sig.bytes != NULL);

	sig.size = nbytes;
	size_t prv_len = 0;

	/* throw the first <offset> number of instructions away */
	for(int i = 0; i < offset; i++) {
		if(inst == NULL)
			break;
		sig.offset += ((strlen(inst->bytes) + 1)/ 3);

		struct instruction *tmp = inst;
		inst = inst->next;
		free(tmp);
	}

	int keep_processing = 1;
	struct instruction *crawler = inst;	
	while(crawler != NULL) {

		if(keep_processing == 1) 
			process_instruction(crawler, &sig);

		/* if max_len is -1 (or just < 0), then there is no limit on the
		 * signature length. */
		if(max_len >= 0 && sig.len >= (size_t)max_len) {
			keep_processing = 0;
			sig.len = prv_len;
		}

		prv_len = sig.len;

		struct instruction *tmp = crawler;

		crawler = crawler->next;

		free(tmp);
	}

	/* overwrite last whitespace with null terminator. */
	sig.bytes[sig.idx-1] = '\0';

	return sig;
}

static char *get_func_data(const char *fcont, const char *func_name)
{
	char buf[255]; 	
	size_t buf_size = ARR_SIZE(buf);
	
	int len = snprintf(buf, buf_size, "<%s>:", func_name);
	assert(len > 0 && len < (int)buf_size);

			
	/* find starting location of "<func_name>:" in the file. */
	char *sloc = get_location(fcont, buf);	
			
	/* find end location of "<func_name>:".I assume that a function will
	 * follow the x86_64 calling convention and end with a "ret" instruction.
	 * */	
	char *eloc = strstr(sloc, "ret");
	assert(eloc != NULL);
	eloc += strlen("ret");

	
	size_t nbytes = (size_t)((uintptr_t)eloc - (uintptr_t)sloc);
	/* + 1 for nullterminator. */
	char *func_data = malloc((sizeof(*func_data) * nbytes) + 1);
	assert(func_data != NULL);

	memcpy(func_data, sloc, nbytes);
	func_data[nbytes] = '\0';


	return func_data;
}


static char *get_location(const char *haystack, const char *needle)
{
	/* search for "<func_name>" in file. There should only be one
	 * occourance. */
	char *loc = strstr(haystack, needle);
	if(loc == NULL) {
		fprintf(stderr, "Error: Function name not found\n");	
		exit(EXIT_FAILURE);
	}

	/* search for the needle ("<func_name>") again to make sure that there
	 * are no duplicates. */
	char *tmp = strstr(loc + 1, needle);
	if(tmp != NULL) {
		fprintf(stderr, "Error: Function name is not unique\n");	
		exit(EXIT_FAILURE);
	}

	return loc;
}


/* returns a null terminated string of the file content. */
static char *get_file_content(const char *path)
{
	FILE *f = fopen(path, "r");
	assert(f != NULL);

	long fsize = get_file_size(f);
	assert(fsize != -1);

	char *fcont = NULL;
	/* + 1 for the null terminator. */
	size_t fcont_size = (sizeof(*fcont) * fsize) + 1;
	fcont = malloc(fcont_size);
	assert(fcont != NULL);

	size_t ret = fread(fcont, sizeof(*fcont), fsize, f);
	assert(ret > 0 && ret == (size_t)fsize);
	
	fcont[ret] = '\0';

	fclose(f);
	return fcont;
}

static long get_file_size(FILE *f)
{
	int ret = fseek(f, 0, SEEK_END);
	assert(ret == 0);

	long fsize = ftell(f);
	assert(fsize != -1);

	rewind(f);

	return fsize;
}
