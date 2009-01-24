/****************************************************************************
 ****************************************************************************
 *
 * gpgwrap.c
 *
 ****************************************************************************
 ****************************************************************************/





#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "version.h"



#define PROGRAM_NAME			"gpgwrap"
#define VERSION_STRING			PROGRAM_NAME " " VERSION "-" VERSION_DATE
#define EXEC_ARGV_SIZE			1024
#define PASSPHRASE_BUFFER_SIZE		0x10000
#define LIST_BUFFER_SIZE		0x10000
#define CMDLINE_MAX_FILES		1024
#define GPGWRAP_MODE_DEFAULT		0
#define GPGWRAP_MODE_VERSION		1
#define GPGWRAP_MODE_FILE		2
#define GPGWRAP_MODE_PRINT		3



static char				program_name[] = PROGRAM_NAME;
static char				environ_name[] = "GPGWRAP_PASSPHRASE";
static int				mode = GPGWRAP_MODE_DEFAULT;
static int				verbose = 0;
static int				interactive = 0;
static int				ask_twice = 0;
static int				check_exit_code = 0;
static char				*calling_path = NULL;
static char				*environ_var = NULL;
static char				*passphrase_file = NULL;
static char				*option_name = "--passphrase-fd";
static char				*files[CMDLINE_MAX_FILES];
static int				nfiles = 0;				
static char				**gpg_cmd = NULL;



/****************************************************************************
 * do_perror
 ****************************************************************************/
static void
do_perror(
	void)

	{
	perror(program_name);
	exit(1);
	}



/****************************************************************************
 * do_error
 ****************************************************************************/
#define do_error(args...)						\
	do								\
		{							\
		fprintf(stderr, "%s: ", program_name);			\
		fprintf(stderr, args);					\
		fprintf(stderr, "\n");					\
		exit(1);						\
		}							\
	while (0)



/****************************************************************************
 * do_warning
 ****************************************************************************/
#define do_warning(args...)						\
	do								\
		{							\
		fprintf(stderr, "%s: ", program_name);			\
		fprintf(stderr, args);					\
		fprintf(stderr, "\n");					\
		}							\
	while (0)



/****************************************************************************
 * do_error_oom
 ****************************************************************************/
static void
do_error_oom(
	void)

	{
	do_error("could not allocate memory");
	}



/****************************************************************************
 * do_error_too_long
 ****************************************************************************/
static void
do_error_too_long(
	void)

	{
	do_error("passphrase too long");
	}



/****************************************************************************
 * do_verbose
 ****************************************************************************/
#define do_verbose(level, args...)					\
	do								\
		{							\
		if (verbose < level) break;				\
		fprintf(stderr, "%s[%d]: ", program_name, getpid());	\
		fprintf(stderr, args);					\
		fprintf(stderr, "\n");					\
		}							\
	while (0)



/****************************************************************************
 * do_verbose_start
 ****************************************************************************/
#define do_verbose_start(level, args...)				\
	do								\
		{							\
		if (verbose < level) break;				\
		fprintf(stderr, "%s[%d] ", program_name, getpid());	\
		fprintf(stderr, args);					\
		}							\
	while (0)



/****************************************************************************
 * do_verbose_append
 ****************************************************************************/
#define do_verbose_append(level, args...)				\
	do								\
		{							\
		if (verbose < level) break;				\
		fprintf(stderr, args);					\
		}							\
	while (0)



/****************************************************************************
 * do_snprintf
 ****************************************************************************/
#define do_snprintf(string, max, args...)	do_snprintf2(snprintf(string, max, args), max)



/****************************************************************************
 * do_snprintf2
 ****************************************************************************/
static int
do_snprintf2(
	int				len,
	int				max)

	{
	if ((len == -1) || (len >= max)) do_error("do_snprintf() size exceeded");
	return (len);
	}



/****************************************************************************
 * mangle_passphrase
 ****************************************************************************/
static int
mangle_passphrase(
	char				*buffer,
	int				size,
	char				*mbuffer,
	int				msize)

	{
	char				c;
	int				i, j, c1;

	/*
	 * look for "unusual" characters and convert them to
	 * backslash escaped octal numbers
	 */

	for (i = j = 0, msize--; i < size; i++)
		{
		c = buffer[i];
		if (j >= msize) goto error;
		if ((c < '+') || ((c > ';') && (c < 'A')) ||
			((c > 'Z') && (c != '_') && (c < 'a')) ||
			((c > 'z') && (c != '~')))
			{
			c1 = (unsigned char) c;
			if (j >= msize - 4) goto error;
			mbuffer[j++] = '\\';
			mbuffer[j++] = '0' + (c1 >> 6);
			mbuffer[j++] = '0' + ((c1 >> 3) & 7);
			mbuffer[j++] = '0' + (c1 & 7);
			}
		else mbuffer[j++] = c;
		}
	mbuffer[j] = '\0';
	return (j);
error:
	do_error("could not mangle passphrase");
	}



/****************************************************************************
 * unmangle_passphrase
 ****************************************************************************/
static int
unmangle_passphrase(
	char				*buffer,
	int				size)

	{
	char				c;
	int				i, j, c1, c2, c3;

	/* replace backslash escaped octal numbers */

	for (i = j = 0; j < size; i++)
		{
		c = buffer[j++];
		if (c == '\\')
			{
			if (j > size - 3) goto error;
			c1 = buffer[j++];
			c2 = buffer[j++];
			c3 = buffer[j++];
			if ((c1 < '0') || (c1 > '3') || (c2 < '0') || (c2 > '7') ||
				(c3 < '0') || (c3 > '7')) goto error;
			c1 -= '0';
			c2 -= '0';
			c3 -= '0';
			c = (char) (((c1 << 6) | (c2 << 3) | c3) & 0xff);
			}
		buffer[i] = c;
		}
	return (i);
error:
	do_error("could not unmangle passphrase");
	}



/****************************************************************************
 * read_passphrase
 ****************************************************************************/
static int
read_passphrase(
	char				*buffer,
	int				size)

	{
	int				fd, len, i;

	do_verbose(2, "reading passphrase from file '%s'", passphrase_file);
	if (strcmp(passphrase_file, "-") == 0) fd = STDIN_FILENO;
	else fd = open(passphrase_file, O_RDONLY);
	if (fd == -1) do_perror();
	for (len = 0; (i = read(fd, buffer, size)) > 0; len += i)
		{
		buffer += i;
		size -= i;
		if (size == 0) do_error_too_long();
		}
	if (i == -1) do_perror();
	if (close(fd) == -1) do_perror();
	return (len);
	}



/****************************************************************************
 * prompt_passphrase
 ****************************************************************************/
static int
prompt_passphrase(
	char				*buffer,
	int				size)

	{
	int				len, len2;
	int				fd;
	struct termios			t, tt;
	char				tty[] = "/dev/tty";
	char				pp[] = "Passphrase: ";
	char				pp2[] = "\nPassphrase (again): ";
	char				*buffer2;

	/*
	 * don't touch stdin, just open the controlling tty and ask for the
	 * passphrase
	 */

	do_verbose(2, "opening '%s' to prompt for passphrase", tty);
	fd = open(tty, O_RDWR);
	if (fd == -1) do_perror();
	write(fd, pp, strlen(pp));
	tcgetattr(fd, &t);
	tt = t;
	tt.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSAFLUSH, &tt);
	len = read(fd, buffer, size);
	if (len == -1) do_perror();
	if ((ask_twice) && (len < size))
		{
		buffer2 = (char *) alloca(sizeof (char) * size);
		if (buffer2 == NULL) do_error_oom();
		write(fd, pp2, strlen(pp2));
		len2 = read(fd, buffer2, size);
		if (len2 == -1) do_perror();
		write(fd, "\n", 1);
		tcsetattr(fd, TCSAFLUSH, &t);
		if ((len != len2) || (memcmp(buffer, buffer2, len) != 0)) do_error("passphrases are not the same");
		}
	else
		{
		write(fd, "\n", 1);
		tcsetattr(fd, TCSAFLUSH, &t);

		/*
		 * if the above read() returns with len == size, we don't
		 * know if there are more bytes, so we assume passphrase is
		 * too long
		 */

		if (len >= size) do_error_too_long();
		}
	if (close(fd) == -1) do_perror();

	/* ignore trailing \012 */

	return (len - 1);
	}



/****************************************************************************
 * environ_or_prompt
 ****************************************************************************/
static int
environ_or_prompt(
	char				*buffer,
	int				size)

	{
	int				len, len2;
	char				*env;

	env = getenv(environ_name);
	if ((env != NULL) && (! interactive))
		{
		do_verbose(2, "got passphrase from environment variable: %s=%s", environ_name, env);

		/*
		 * first unmangle the content of the environment
		 * variable inplace, then clear the memory
		 */

		len2 = strlen(env);
		len = unmangle_passphrase(env, len2);
		if (len > size) do_error_too_long();
		memcpy(buffer, env, len);
		memset(env, 0, len2);
		}
	else len = prompt_passphrase(buffer, size);
	return (len);
	}



/****************************************************************************
 * do_wait
 ****************************************************************************/
static void
do_wait(
	void)

	{
	int				status, value = 1;

	do_verbose(2, "waiting for child");
	wait(&status);
	if (! check_exit_code) return;
	do_verbose(2, "checking child exit code");
	if (! WIFEXITED(status)) goto out;
	value = WEXITSTATUS(status);
	if (value == 0) return;
	do_verbose(2, "child process terminated abnormal, exiting");
out:
	exit(value);
	}



/****************************************************************************
 * do_fork
 ****************************************************************************/
static int
do_fork(
	char				*buffer,
	int				size)

	{
	int				fds[2], i;

	/*
	 * parent will write passphrase to the opened pipe, child will
	 * pass the fd to gpg
	 */

	if (pipe(fds) == -1) do_perror();
	do_verbose(2, "forking");
	switch (fork())
		{
		case -1:
			do_perror();
		case 0:
			/* child */

			if (close(fds[1]) == -1) do_perror();
			return (fds[0]);
		default:
			break;
		}

	/* parent */

	signal(SIGPIPE, SIG_IGN);
	if (close(fds[0]) == -1) do_perror();
	while (size > 0)
		{
		i = write(fds[1], buffer, size);
		if ((i == -1) && (errno == EPIPE)) break;
		if (i == -1) do_perror();
		buffer += i;
		size -= i;
		}
	if (size > 0) do_warning("only partial passphrase written");
	if (close(fds[1]) == -1) do_perror();
	do_wait();
	return (-1);
	}



/****************************************************************************
 * get_passphrase_fd
 ****************************************************************************/
static int
get_passphrase_fd(
	void)

	{
	int				fd, len;
	char				buffer[PASSPHRASE_BUFFER_SIZE];

	if ((passphrase_file == NULL) || (interactive))
		{
		len = environ_or_prompt(buffer, sizeof (buffer));
		fd = do_fork(buffer, len);
		}
	else if (strcmp(passphrase_file, "-") == 0)
		{
		len = read_passphrase(buffer, sizeof (buffer));
		fd = do_fork(buffer, len);
		}
	else
		{
		do_verbose(2, "opening file '%s' to pass fd", passphrase_file);
		fd = open(passphrase_file, O_RDONLY);
		if (fd == -1) do_perror();
		}
	return (fd);
	}



/****************************************************************************
 * get_passphrase
 ****************************************************************************/
static int
get_passphrase(
	char				*buffer,
	int				size)

	{
	int				len;

	if ((passphrase_file == NULL) || (interactive)) len = environ_or_prompt(buffer, size);
	else len = read_passphrase(buffer, size);
	return (len);
	}



/****************************************************************************
 * do_putenv
 ****************************************************************************/
static void
do_putenv(
	char				*buffer,
	int				len)

	{
	int				size, len2;
	char				*old_var;

	/*
	 * putenv() only stores the given pointer in **environ, so we have
	 * to use malloc here
	 */

	size = strlen(environ_name) + (4 * len) + 2;
	old_var = environ_var;
	environ_var = (char *) malloc(sizeof (char) * size);
	if (environ_var == NULL) do_error_oom();
	len2 = do_snprintf(environ_var, size, "%s=", environ_name);
	if ((buffer != NULL) && (len > 0)) mangle_passphrase(buffer, len, &environ_var[len2], size - len2);
	do_verbose(2, "setting environment variable: %s", environ_var);
	if (putenv(environ_var) == -1) do_perror();
	if (old_var != NULL) free(old_var);
	}



/****************************************************************************
 * do_exec
 ****************************************************************************/
static void
do_exec(
	char				**argv,
	int				clear)

	{
	if (clear) do_putenv(NULL, 0);
	if (verbose > 0)
		{
		int			i;

		do_verbose_start(1, "executing:");
		for (i = 0; argv[i] != NULL; i++) do_verbose_append(1, " %s", argv[i]);
		do_verbose_append(1, "\n");
		}
	execvp(argv[0], argv);

	/* only reached if execvp fails */

	do_perror();
	}



/****************************************************************************
 * exec_gpg
 ****************************************************************************/
static void
exec_gpg(
	void)

	{
	int				fd;
	int				i, j, k;
	char				fd_num[32];
	char				*argv[EXEC_ARGV_SIZE];
	char				homedir_eq[] = "--homedir=";
	char				options_eq[] = "--options=";

	/*
	 * get fd to read passphrase from, parent will return with fd == -1
	 * after fork
	 */

	fd = get_passphrase_fd();
	if (fd == -1) return;

	/* create argv for execvp */

	do_snprintf(fd_num, sizeof (fd_num), "%d", fd);
	for (i = 0, j = 0, k = 1; gpg_cmd[i] != NULL; i++, k--)
		{

		/*
		 * check if there is enough space to store option_name
		 * and fd_num
		 */

		if (i >= (EXEC_ARGV_SIZE - 4)) do_error("too many gpg arguments specified");
		if (strcmp(gpg_cmd[i], option_name) == 0) do_error("gpg command already has a '%s' option", option_name);
		if (k == 0)
			{
			if ((strncmp(gpg_cmd[i], homedir_eq, sizeof (homedir_eq) - 1) == 0) || (strncmp(gpg_cmd[i], options_eq, sizeof (options_eq) - 1) == 0)) k = 1;
			else if ((strcmp(gpg_cmd[i], "--homedir") == 0) || (strcmp(gpg_cmd[i], "--options") == 0)) k = 2;
			else
				{
				argv[j++] = option_name;
				argv[j++] = fd_num;
				}
			}
		argv[j++] = gpg_cmd[i];
		}
	if (k >= 0)
		{
		argv[j++] = option_name;
		argv[j++] = fd_num;
		}
	argv[j] = NULL;
	do_exec(argv, 1);
	}



/****************************************************************************
 * exec_line
 ****************************************************************************/
static void
exec_line(
	char				*line)

	{
	char				shell_cmd[LIST_BUFFER_SIZE];
	char				verbose_string[128] = "";
	char				*argv[] = { "sh", "-c", NULL, NULL };
	int				fds[2], i;

	/* fork a child and disallow it to read stdin from parent */

	if (pipe(fds) == -1) do_perror();
	do_verbose(1, "forking");
	switch (fork())
		{
		case -1:
			do_perror();
		case 0:
			break;
		default:
			/* parent */

			if (close(fds[0]) == -1) do_perror();
			if (close(fds[1]) == -1) do_perror();
			do_wait();
			return;
		}

	/* child */

	if (close(fds[1]) == -1) do_perror();
	if (fds[0] != STDIN_FILENO) dup2(fds[0], STDIN_FILENO);

	/* create argv for execvp */

	for (i = 0; i < verbose; i++)
		{
		if (strlen(verbose_string) >= sizeof (verbose_string) - 4) break;
		strcat(verbose_string, " -v");
		}
	do_snprintf(shell_cmd, sizeof (shell_cmd), "exec %s%s -o %s -- %s",
		calling_path, verbose_string, option_name, line);
	argv[2] = shell_cmd;
	do_exec(argv, 0);
	}



/****************************************************************************
 * exec_list
 ****************************************************************************/
static void
exec_list(
	char				*path,
	char				*buffer,
	int				len)

	{
	int				fd;
	char				lbuffer[LIST_BUFFER_SIZE];
	int				inuse, start, free, nread, llen;
	char				*line, *next_line;

	/* open file */

	do_verbose(1, "reading gpg commands from file: '%s'", path);
	if (strcmp(path, "-") == 0) fd = STDIN_FILENO;
	else fd = open(path, O_RDONLY);
	if (fd == -1) do_perror();

	/* export passphrase to environment */

	do_putenv(buffer, len);

	/* read gpg commands */

	for (inuse = 0, free = LIST_BUFFER_SIZE; (nread = read(fd, &lbuffer[inuse], free)) > 0; )
		{
		inuse += nread;
		for (line = lbuffer; (next_line = memchr(line, '\n', inuse)) != NULL; )
			{
			*next_line = '\0';
			llen = (int) (next_line - line) + 1;
			if (llen != strlen(line) + 1) do_error("line contains \\0 character");
			exec_line(line);
			inuse -= llen;
			line = next_line + 1;
			}
		start = (int) (line - lbuffer);
		if ((start == 0) && (inuse == LIST_BUFFER_SIZE)) do_error("line too long");
		if ((start > 0) && (inuse > 0)) memmove(lbuffer, &lbuffer[start], inuse);
		free = LIST_BUFFER_SIZE - inuse;
		}

	/* check for error while read() */

	if (nread == -1) do_perror();
	if (close(fd) == -1) do_perror();

	/* check if there are bytes left */

	if (inuse > 0) do_error("last line incomplete");
	}



/****************************************************************************
 * cmdline_fill_space
 ****************************************************************************/
static void
cmdline_fill_space(
	char				*s)

	{
	while (*s != '\0') *s++ = ' ';
	}



/****************************************************************************
 * cmdline_usage
 ****************************************************************************/
static void
cmdline_usage(
	void)

	{
	char				space1[] = VERSION_STRING;
	char				space2[] = PROGRAM_NAME;

	cmdline_fill_space(space1);
	cmdline_fill_space(space2);
	printf(VERSION_STRING " | written by Karsten Scheibler\n"
		"%s | http://unusedino.de/gpgwrap/\n"
		"%s | gpgwrap@unusedino.de\n\n"
		"Usage: %s -V\n"
		"or:    %s -P [-v] [-i] [-a] [-p <file>]\n"
		"or:    %s -F [-v] [-i] [-a] [-c] [-p <file>] [-o <name>]\n"
		"       %s    [--] <file> [<file> ... ]\n"
		"or:    %s [-v] [-i] [-a] [-p <file>] [-o <name>]\n"
		"       %s [--] gpg [gpg options]\n\n"
		"  -V          print out version\n"
		"  -P          get the passphrase and print it mangled to stdout\n"
		"  -F          read gpg commands from file\n"
		"  -v          be more verbose\n"
		"  -i          be interactive, always prompt for passphrase\n"
		"  -a          ask twice if prompting for passphrase\n"
		"  -c          check exit code of child processes\n"
		"  -p <file>   read passphrase from <file>\n"
		"  -o <name>   specify name of \"--passphrase-fd\" option\n"
		"  -h          this help\n",
		space1, space1, program_name, program_name, program_name,
		space2, program_name, space2);
	exit(0);
	}



/****************************************************************************
 * cmdline_check_arg
 ****************************************************************************/
static char *
cmdline_check_arg(
	char				*msg,
	char				*file)

	{
	if (file == NULL) do_error("%s expects a file name", msg);
	return (file);
	}



/****************************************************************************
 * cmdline_check_stdin
 ****************************************************************************/
static char *
cmdline_check_stdin(
	char				*msg,
	char				*file)

	{
	static int			stdin_count = 0;

	cmdline_check_arg(msg, file);
	if (strcmp(file, "-") == 0) stdin_count++;
	if (stdin_count > 1) do_error("%s used stdin although already used before", msg);
	return (file);
	}



/****************************************************************************
 * cmdline_parse
 ****************************************************************************/
static void
cmdline_parse(
	int				argc,
	char				**argv)

	{
	char				*arg;
	int				args;
	int				ignore = 0;

	calling_path = argv[0];
	for (args = 0, argv++; (arg = *argv++) != NULL; args++)
		{
		if ((arg[0] != '-') || (ignore))
			{
			if (mode == GPGWRAP_MODE_FILE) goto get_file;
			gpg_cmd = argv - 1;
			break;
			}
		else if ((strcmp(arg, "-") == 0) && (mode == GPGWRAP_MODE_FILE))
			{
		get_file:
			if (nfiles >= CMDLINE_MAX_FILES) do_error("too many files specified");
			files[nfiles++] = cmdline_check_stdin("-F/--file", arg);
			}
		else if (strcmp(arg, "--") == 0)
			{
			ignore = 1;
			}
		else if ((strcmp(arg, "-h") == 0) || (strcmp(arg, "--help") == 0))
			{
			cmdline_usage();
			}
		else if (((strcmp(arg, "-V") == 0) || (strcmp(arg, "--version") == 0)) && (args == 0))
			{
			mode = GPGWRAP_MODE_VERSION;
			}
		else if (((strcmp(arg, "-F") == 0) || (strcmp(arg, "--file") == 0)) && (args == 0))
			{
			mode = GPGWRAP_MODE_FILE;
			}
		else if (((strcmp(arg, "-P") == 0) || (strcmp(arg, "--print") == 0)) && (args == 0))
			{
			mode = GPGWRAP_MODE_PRINT;
			}
		else if (mode == GPGWRAP_MODE_VERSION)
			{
			goto bad_option;
			}
		else if ((strcmp(arg, "-v") == 0) || (strcmp(arg, "--verbose") == 0))
			{
			verbose++;
			}
		else if ((strcmp(arg, "-i") == 0) || (strcmp(arg, "--interactive") == 0))
			{
			interactive = 1;
			}
		else if ((strcmp(arg, "-a") == 0) || (strcmp(arg, "--ask-twice") == 0))
			{
			ask_twice = 1;
			}
		else if ((strcmp(arg, "-p") == 0) || (strcmp(arg, "--passphrase-file") == 0))
			{
			if (passphrase_file != NULL) do_error("-p/--passphrase-file specified more than once");
			passphrase_file = cmdline_check_stdin("-p/--passphrase-file", *argv++);
			}
		else if (mode == GPGWRAP_MODE_PRINT)
			{
			goto bad_option;
			}
		else if ((strcmp(arg, "-o") == 0) || (strcmp(arg, "--option-name") == 0))
			{
			option_name = cmdline_check_arg("-o/--option-name", *argv++);
			}
		else if (mode != GPGWRAP_MODE_FILE)
			{
			goto bad_option;
			}
		else if ((strcmp(arg, "-c") == 0) || (strcmp(arg, "--check-exit-code") == 0))
			{
			check_exit_code = 1;
			}
		else
			{
		bad_option:
			do_error("unrecognized option '%s'", arg);
			}
		}
	if ((mode == GPGWRAP_MODE_DEFAULT) && (nfiles == 0) && (gpg_cmd == NULL)) do_error("no gpg command specified");
	if ((mode == GPGWRAP_MODE_FILE) && (nfiles == 0)) do_error("no files to process");
	if ((mode == GPGWRAP_MODE_PRINT) && (nfiles > 0)) do_error("no additional arguments allowed");
	if (mode != GPGWRAP_MODE_FILE) check_exit_code = 1;
	}



/****************************************************************************
 * main
 ****************************************************************************/
int
main(
	int				argc,
	char				**argv)

	{

	/*
	 * we need setlinebuf(), because otherwise do_verbose() output of
	 * parent and child processes may get mixed in some cases
	 */

	setlinebuf(stderr);

	/* parse cmdline */

	cmdline_parse(argc, argv);

	/* do it */

	if (mode == GPGWRAP_MODE_VERSION)
		{
		printf(VERSION_STRING "\n");
		}
	else if (mode == GPGWRAP_MODE_FILE)
		{
		int			i, len;
		char			buffer[PASSPHRASE_BUFFER_SIZE];

		len = get_passphrase(buffer, sizeof (buffer));
		for (i = 0; i < nfiles; i++) exec_list(files[i], buffer, len);
		}
	else if (mode == GPGWRAP_MODE_PRINT)
		{
		char			buffer[PASSPHRASE_BUFFER_SIZE];
		char			mbuffer[PASSPHRASE_BUFFER_SIZE];
		int			len;

		len = get_passphrase(buffer, sizeof (buffer));
		mangle_passphrase(buffer, len, mbuffer, sizeof (mbuffer));
		printf("%s\n", mbuffer);
		}
	else exec_gpg();

	/* done */

	return (0);
	}
/******************************************************** Karsten Scheibler */
