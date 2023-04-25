/*
 * This file is part of ALSA HTTP streaming server.
 *
 * Copyright (c) 2023 Aleksander Mazur
 *
 * ALSA HTTP streaming server is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * ALSA HTTP streaming server is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ALSA HTTP streaming server. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <endian.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <getopt.h>
#include <syslog.h>
#include <alsa/asoundlib.h>

/**
 * @defgroup main The only module
 * @{
 */

/** If assertion fails, prints a message to syslog and aborts the program. */
#define	ASSERT(x)	do { if (!(x)) { syslog(LOG_CRIT, "%s:%d: assertion failed: %s", __FILE__, __LINE__, #x); abort(); } } while (0)

/**************************************/

/**
 * Sets O_NONBLOCK flag on a file descriptor.
 *
 * @param fd File descriptor to be made non-blocking.
 * @return 0 on success.
 */
static int setnonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return flags;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * Formats Internet socket address as a string inside a static buffer
 * for immediate use.
 *
 * @param addr Internet socket address.
 * @return Pointer to a static buffer holding a string terminated by nul char.
 */
static const char *format_addr(const struct sockaddr_in *addr)
{
	static char buf[128];

	if (getnameinfo((const struct sockaddr *) addr, sizeof(*addr), buf, sizeof(buf), NULL, 0, 0)) {
		snprintf(buf, sizeof(buf), "%s:%hu", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	} else {
		size_t len = strlen(buf);

		if (len < sizeof(buf)) {
			snprintf(buf + len, sizeof(buf) - len, ":%hu", ntohs(addr->sin_port));
		}
	}

	return buf;
}

/**
 * Parses software volume control settings.
 *
 * @param [in] p Pointer to a string where software volume control settings should be present.
 * @param [out] pa256 A/256 multiplier.
 * @param [out] pb Negated DC bias of input signal (what to add to the signal before multiplication).
 * @param [out] pshl Binary logarithm of A multiplier, or 0 if it can't be exactly computed as an integer.
 * @return 0 on success.
 */
static int parse_softvol(const char *p, int *pa256, int *pb, int *pshl)
{
	unsigned b, neg_b = 0, shl;
	int val, c = sscanf(p, "%d+%u", pa256, &b);
	if (c != 2) {
		c = sscanf(p, "%d-%u", pa256, &b);
		neg_b++;
	}
	if (c == 1)
		b = 0;
	if (c < 1 || c > 2 || *pa256 < -65536*256 || *pa256 > 65536*256 || b > 65536*256)
		return 1;
	*pb = neg_b ? -(int) b : (int) b;
	for (shl = 0, val = 256; val && val < *pa256; shl++, val <<= 1)
		;
	*pshl = val == *pa256 ? shl : 0;
	return 0;
}

/**************************************/

/**
 * Initializes the program.
 *
 * Called before parsing configuration.
 *
 * @param argv0 0th command line argument.
 * @return Name of the program.
 */
static const char *preinit_program(const char *argv0)
{
	const char *pwd = getenv("PWD");
	const char *name = strrchr(argv0, '/');
	if (pwd) {
		pwd = strrchr(pwd, '/');
		if (pwd)
			pwd++;
	}
	if (!name++)
		name = argv0;
	if (pwd && !memcmp(pwd, name, strlen(name)))
		name = pwd;

	return name;
}

/**************************************/

/** ALSA capture device. */
static char *config_dev = "default";
/** PCM sample rate. */
static unsigned config_rate = 24000;
/** Fake output sample rate, or 0 if real rate should be used. */
static unsigned config_override_rate = 0;
/** Number of audio channels. 0 = autodetect minimum supported value. */
static unsigned config_channels = 0;
/** PCM capture buffer length, in ms. */
static unsigned config_capture_buffer = 500000;
/** PCM capture period length, in ms. */
static unsigned config_capture_period = 50000;
/** PCM playback buffer length, in ms. */
static unsigned config_playback_buffer = 5000000;
/** PCM playback period length, in ms. */
static unsigned config_playback_period;
/** How many times our own buffer should be bigger than that in ALSA. */
static unsigned config_buf_mul = 1;
/** A file where static runtime information (including TCP port number and sound card info) will be stored. */
static char *config_info_file = NULL;
/** A file where dynamic runtime information will be stored. */
static char *config_status_file = NULL;
/** Verbose output switch. */
static unsigned config_verbose = 0;
/** What to write to a file to keep the audio alive. */
static char *config_keep_alive_what;
/** Where to write @c config_keep_alive_what to keep the audio alive. */
static char *config_keep_alive_to;
/** How often to write @c config_keep_alive_what to @c config_keep_alive_to to keep the audio alive (period in seconds). */
static unsigned config_keep_alive_period = 55;
/** Path to a pipe we will create and read commands from. */
static const char *config_pipe = "ctl";
/** When configuration of software parameters of ALSA playback device fails, re-try with device name prefixed with this. */
static const char *config_auto_prefix_inval = "plug";
/** Software volume control - multiplier. */
static int softvol_a256 = 256;
/** Software volume control - offset before multiplication. */
static int softvol_b;
/** Software volume control - shift left (computed from @ref softvol_a256) or 0 if there is no shift left equivalent of multiplying by @ref softvol_a256. */
static int softvol_shl = 0;
/** Only save info about playback device and exit. */
static unsigned config_play_info;
/** How many times to retry if opening given device fails (workaround for ALSA not ready immediately after uevent "add"). */
static unsigned config_info_retry = 9;

/** Executes given statement only if @ref config_verbose is enabled. */
#define	VERBOSE(x)	do { if (config_verbose) x; } while (0)

/**************************************/

/**
 * Prints usage help.
 *
 * @param name Name of our program.
 */
static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Available options (with their default values):\n"
		"\t-C|--dev\tALSA capture device, e.g. hw:0,0 (default)\n"
		"\t-r|--rate\tPCM sample rate [Hz] (24000)\n"
		"\t--fake-rate\toverride output PCM sample rate [Hz]\n"
		"\t-c|--channels\tNumber of audio channels (minimum supported)\n"
		"\t-b|--buffer\tALSA buffer length [us] (500000)\n"
		"\t-d|--period\tALSA period length [us] (50000)\n"
		"\t-m|--multiplier\tHow many times our buffer is bigger than ALSA's (1)\n"
		"\t-i|--info\tFile where static runtime info should be written\n"
		"\t-s|--status\tFile where dynamic runtime info should be written\n"
		"\t--keep-alive-what\tKeep alive content\n"
		"\t--keep-alive-to\tKeep alive file\n"
		"\t--keep-alive-period\tKeep alive period [s]\n"
		"\t-o|--only-play-info\tSave info about playback dev and exit\n"
		"\t-V|--vol\tSoftware volume control: a/256{+|-}b (256+0)\n"
		"\t-v|--verbose\tIncrease verbosity level (quiet)\n"
		"\t-h|--help\tPrint this information and exit\n"
		, name);
}

/**
 * Parses options from command line.
 *
 * @param name Name of our program.
 * @param argc Number of command line arguments.
 * @param argv Array of command line arguments.
 * @return 0 on success.
 */
static int configure(const char *name, int argc, char **argv)
{
	static char *opt_short = "C:r:c:b:d:m:i:s:V:ot:vh";
	static struct option opt_long[] = {
		{ "dev", required_argument, NULL, 'C' },
		{ "rate", required_argument, NULL, 'r' },
		{ "fake-rate", required_argument, NULL, 3 },
		{ "channels", required_argument, NULL, 'c' },
		{ "buffer", required_argument, NULL, 'b' },
		{ "period", required_argument, NULL, 'd' },
		{ "playback-buffer", required_argument, NULL, 1 },
		{ "playback-period", required_argument, NULL, 2 },
		{ "multiplier", required_argument, NULL, 'm' },
		{ "info", required_argument, NULL, 'i' },
		{ "status", required_argument, NULL, 's' },
		{ "keep-alive-what", required_argument, NULL, 'w' },
		{ "keep-alive-to", required_argument, NULL, 4 },
		{ "keep-alive-period", required_argument, NULL, 'e' },
		{ "vol", required_argument, NULL, 'V' },
		{ "retry", required_argument, NULL, 't' },
		{ "only-play-info", no_argument, NULL, 'o' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, }
	};
	unsigned invalid = 0;
	int c;

	while ((c = getopt_long(argc, argv, opt_short, opt_long, NULL)) != -1) {
		switch (c) {
			case 'C':
				config_dev = optarg;
				break;
			case 'r':
				config_rate = atoi(optarg);
				break;
			case 3:
				config_override_rate = atoi(optarg);
				break;
			case 'c':
				config_channels = atoi(optarg);
				break;
			case 'b':
				config_capture_buffer = atoi(optarg);
				break;
			case 'd':
				config_capture_period = atoi(optarg);
				break;
			case 1:
				config_playback_buffer = atoi(optarg);
				break;
			case 2:
				config_playback_period = atoi(optarg);
				break;
			case 'm':
				config_buf_mul = atoi(optarg);
				break;
			case 'i':
				config_info_file = optarg;
				break;
			case 's':
				config_status_file = optarg;
				break;
			case 'w':
				config_keep_alive_what = optarg;
				break;
			case 4:
				config_keep_alive_to = optarg;
				break;
			case 'e':
				config_keep_alive_period = atoi(optarg);
				break;
			case 'V':
				if (parse_softvol(optarg, &softvol_a256, &softvol_b, &softvol_shl))
					invalid++;
				break;
			case 'o':
				config_play_info++;
				break;
			case 't':
				config_info_retry = atoi(optarg);
				break;
			case 'v':
				config_verbose++;
				break;
			case 'h':
				usage(name);
				exit(0);
				break;
			case '?':
				invalid++;
				break;
			default:
				ASSERT(0);
				break;
		}
	}

	if (optind < argc) {
		fputs("What did you try to accomplish by passing", stdout);
		for (c = optind; c < argc; c++) {
			putchar(' ');
			fputs(argv[c], stdout);
		}
		puts("?");
	}
	if (invalid || optind < argc) {
		usage(name);
		return 1;
	}

	if (!config_playback_buffer)
		config_playback_buffer = config_capture_buffer;
	if (!config_playback_period)
		config_playback_period = config_capture_period;
	return 0;
}

/**************************************/

/**
 * Saves information about selected ALSA capture device.
 *
 * @param port TCP port number of our listening socket. 0 means we're
 *             not going to listen on any port; instead, information
 *             about playback device should be saved.
 * @return 0 on success.
 */
static int save_info(unsigned port)
{
	FILE *f;

	if (!config_info_file && !config_play_info)
		return 0;

	f = config_info_file ? fopen(config_info_file, "w") : stdout;
	if (f) {
		snd_pcm_t *alsa;
		int err;
		unsigned retry = config_info_retry;

		for (;; retry--) {
			err = snd_pcm_open(&alsa, config_dev, port ? SND_PCM_STREAM_CAPTURE : SND_PCM_STREAM_PLAYBACK, 0);

			if (!err || !retry)
				break;

			sleep(1);
		}

		if (err) {
			syslog(LOG_ERR, "ALSA: unable to open %s: %s", config_dev, snd_strerror(err));
		} else {
			snd_pcm_info_t *info;

			if (retry != config_info_retry)
				syslog(LOG_INFO, "ALSA: opened %s after %u retries", config_dev, config_info_retry - retry);

			fprintf(f, "type=%s\n", snd_pcm_type_name(snd_pcm_type(alsa)));

			if (!snd_pcm_info_malloc(&info)) {
				err = snd_pcm_info(alsa, info);

				if (!err) {
					const char *id = snd_pcm_info_get_id(info);
					const char *name = snd_pcm_info_get_name(info);

					fprintf(f, "name=%s", id);
					if (strcmp(id, name))
						fprintf(f, " - %s", name);
					fputc('\n', f);
				} else {
					syslog(LOG_ERR, "ALSA: unable to get info about %s: %s", config_dev, snd_strerror(err));
				}

				snd_pcm_info_free(info);
			}

			snd_pcm_close(alsa);
		}

		if (port)
			fprintf(f, "port=%u\n", port);

		if (f != stdout)
			fclose(f);
		return 0;
	} else {
		syslog(LOG_ERR, "writing %u to %s: %s", port, config_info_file, strerror(errno));
	}
	/*
	pid_t pid = fork();

	if (pid > 0) {
		// we're the parent
		return 0;	// OK
	} else if (!pid) {
		// we're the child
		char buf[10] = "0";
		snprintf(buf, sizeof(buf), "%u", port);
		execl(config_script, config_script, buf, NULL);
		syslog(LOG_ERR, "exec %s %s: %s", config_script, buf, strerror(errno));
		_exit(1);
	}
	*/

	return 4;
}

/**************************************/

/**
 * Configures ALSA HW params.
 *
 * @param [in,out] handle ALSA PCM handle.
 * @param [in] buffer_time PCM buffer length, in ms.
 * @param [in] period_time PCM period length, in ms.
 * @param [in] channels Required number of channels. 0 = default.
 * @param [in] rate Required sample rate. 0 = default.
 * @param [out] pchannels Pointer to a variable which receives actual number of audio channels.
 * @param [out] prate Pointer to a variable which receives actual sample rate.
 * @param [out] pbuffer_size Pointer to a variable which receives actual buffer size (in samples=frames).
 * @param [out] pperiod_size Pointer to a variable which receives actual period size (in samples=frames).
 * @return 0 on success.
 */
static int alsa_set_hwparams(snd_pcm_t *handle, unsigned buffer_time, unsigned period_time, unsigned channels, unsigned rate, unsigned *pchannels, unsigned *prate, snd_pcm_uframes_t *pbuffer_size, snd_pcm_uframes_t *pperiod_size)
{
	snd_pcm_hw_params_t *params;
	unsigned periods_cnt = buffer_time / period_time;
	int err;

	snd_pcm_hw_params_alloca(&params);
	// choose all parameters
	err = snd_pcm_hw_params_any(handle, params);
	if (err < 0) {
		syslog(LOG_WARNING, "No configurations available: %s", snd_strerror(err));
		return err;
	}
	// allow software resampling only if particular rate is specified (= for playback with same rate as capture)
	err = snd_pcm_hw_params_set_rate_resample(handle, params, !!rate);
	if (err < 0) {
		syslog(LOG_WARNING, "Resampling setup failed: %s", snd_strerror(err));
		return err;
	}
	// set the interleaved read/write format
	err = snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
	if (err < 0) {
		syslog(LOG_WARNING, "Interleaved R/W access type not available: %s", snd_strerror(err));
		return err;
	}
	// set the sample format
	err = snd_pcm_hw_params_set_format(handle, params, SND_PCM_FORMAT_S16_LE);
	if (err < 0) {
		syslog(LOG_WARNING, "Sample format S16LE not available: %s", snd_strerror(err));
		return err;
	}
	// set the count of channels
	if (!channels)
		channels = config_channels;
	if (!channels) {
		err = snd_pcm_hw_params_get_channels_min(params, &channels);
		if (err < 0) {
			syslog(LOG_WARNING, "Number of channels not available: %s", snd_strerror(err));
			return err;
		}
	}
	err = snd_pcm_hw_params_set_channels(handle, params, channels);
	if (err < 0) {
		syslog(LOG_WARNING, "%u channels not available: %s", channels, snd_strerror(err));
		return err;
	}
	*pchannels = channels;
	// set the stream rate
	if (rate) {
		err = snd_pcm_hw_params_set_rate(handle, params, rate, 0);
	} else {
		rate = config_rate;
		err = snd_pcm_hw_params_set_rate_near(handle, params, &rate, NULL);
	}
	if (err < 0) {
		syslog(LOG_WARNING, "Rate %uHz not available: %s", rate, snd_strerror(err));
		return err;
	}
	*prate = rate;
	// set the buffer time
	err = snd_pcm_hw_params_set_buffer_time_near(handle, params, &buffer_time, NULL);
	if (err < 0) {
		syslog(LOG_WARNING, "Unable to set buffer time %u: %s", buffer_time, snd_strerror(err));
		return err;
	}
	// set the period time
	err = snd_pcm_hw_params_set_period_time_near(handle, params, &period_time, NULL);
	if (err < 0) {
		syslog(LOG_WARNING, "Unable to set period time %u: %s", period_time, snd_strerror(err));
		return err;
	}
	VERBOSE(syslog(LOG_DEBUG, "buffer=%u period=%u", buffer_time, period_time));
	// set the periods count
	err = snd_pcm_hw_params_set_periods_near(handle, params, &periods_cnt, NULL);
	if (err < 0) {
		syslog(LOG_WARNING, "Unable to set periods %u: %s", periods_cnt, snd_strerror(err));
		return err;
	}
	err = snd_pcm_hw_params_get_buffer_size(params, pbuffer_size);
	if (err < 0) {
		syslog(LOG_WARNING, "Unable to get buffer size: %s", snd_strerror(err));
		return err;
	}
	err = snd_pcm_hw_params_get_period_size(params, pperiod_size, NULL);
	if (err < 0 || *pperiod_size <= 0) {
		syslog(LOG_WARNING, "Unable to get period size: %s", snd_strerror(err));
		return err;
	}
	// write the parameters to device
	err = snd_pcm_hw_params(handle, params);
	if (err < 0) {
		syslog(LOG_WARNING, "Unable to set hw params: %s", snd_strerror(err));
		return err;
	}
	return 0;
}

/**
 * Configures ALSA SW params.
 *
 * @param handle ALSA PCM handle.
 * @param buffer_size Buffer size, in samples=frames.
 * @param period_size Period size, in samples=frames.
 * @return 0 on success.
 */
static int alsa_set_swparams(snd_pcm_t *handle, snd_pcm_uframes_t buffer_size, snd_pcm_uframes_t period_size)
{
	snd_pcm_sw_params_t *swparams;
	int err;

	snd_pcm_sw_params_alloca(&swparams);
	// get the current swparams
	err = snd_pcm_sw_params_current(handle, swparams);
	if (err < 0) {
		syslog(LOG_WARNING, "Unable to determine current swparams: %s", snd_strerror(err));
		return err;
	}
	// start the transfer when the buffer is almost full
	err = snd_pcm_sw_params_set_start_threshold(handle, swparams, (buffer_size / period_size) * period_size);
	if (err < 0) {
		syslog(LOG_WARNING, "Unable to set start threshold: %s", snd_strerror(err));
		return err;
	}
	// allow the transfer when at least period_size samples can be processed
	err = snd_pcm_sw_params_set_avail_min(handle, swparams, period_size);
	if (err < 0) {
		syslog(LOG_WARNING, "Unable to set avail min: %s", snd_strerror(err));
		return err;
	}
	// write the parameters to the capture device
	err = snd_pcm_sw_params(handle, swparams);
	if (err < 0) {
		syslog(LOG_WARNING, "Unable to set sw params: %s", snd_strerror(err));
		return err;
	}
	return 0;
}

/**************************************/

/**
 * Creates listening TCP/IP socket and save related information to @ref config_info_file if succeeded.
 *
 * @return File descriptor of the socket, or a negative value on error.
 */
static int create_server_socket(void)
{
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sock >= 0) {
		do {
			struct sockaddr_in addr;
			socklen_t len;

			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;

			if (bind(sock, (const struct sockaddr *) &addr, sizeof(addr)))
				break;

			len = sizeof(addr);
			if (getsockname(sock, (struct sockaddr *) &addr, &len))
				break;

			if (setnonblock(sock))
				break;

			if (listen(sock, 5))
				break;

			if (save_info(ntohs(addr.sin_port)))
				break;

			return sock;
		} while (0);

		close(sock);
	}

	syslog(LOG_ERR, "socket: %s", strerror(errno));
	return -1;
}

/**************************************/

/**
 * Initializes a pipe for reading commands.
 *
 * @param path Where to set up a pipe.
 * @return 0 on success.
 */
static int init_pipe(const char *path)
{
	const char *msg = NULL;

	do {
		struct stat st;
		int rv = stat(path, &st);

		if (!rv) {
			if ((st.st_mode & S_IFMT) == S_IFIFO)
				return 0;
			msg = "exists and is not a pipe";
			break;
		} else if (errno != ENOENT) {
			break;
		}
		if (mkfifo(path, 0620))
			break;
		if (chmod(path, 0620))	// overcomes umask
			break;
		return 0;
	} while (0);

	syslog(LOG_ERR, "creating%s: %s", path, msg ? msg : strerror(errno));
	return -1;
}

/**************************************/

/** Prefix of a valid query expected from client. */
static const char client_query_pfx[] = "GET /cgi-bin/audio.";
/** HTTP headers of our response. */
static const char client_response_header_template[] = "HTTP/1.0 200 OK\r\n"
	"Server: OLO WAV streaming server " __DATE__ "\r\n"
	"Content-Type: audio/wav\r\n"
	"Pragma: no-cache\r\n"
	"Connection: close\r\n"
	"\r\n";

/** WAV substructure. */
typedef struct {
	uint16_t tag;		/**< Format tag. */
	uint16_t channels;	/**< Number of channels. */
	uint32_t sps;		/**< Samples per second. */
	uint32_t bps;		/**< Bits per sample. */
	uint16_t block;		/**< Bits per block (one sample for all channels). */
	uint16_t sample;	/**< Bits per sample (single channel). */
} waveformatex_t;

/** WAV header. */
typedef struct {
	char riff[4];		/**< "RIFF" header tag. */
	uint32_t riff_size;	/**< RIFF file size.  */
	char fourcc[4];		/**< "WAVE" tag. */
	char fmt_tag[4];	/**< "fmt " chunk tag. */
	uint32_t fmt_size;	/**< Size of the following "fmt " chunk. */
	waveformatex_t fmt;	/**< Content of "fmt " chunk. */
	char data_tag[4];	/**< "data" chunk tag. */
	uint32_t data_size;	/**< Size of the following "data" chunk. */
} wav_hdr_t;

/** Data associated with each connected client. */
typedef struct {
	/** Peer adress. */
	struct sockaddr_in addr;
	/** Union of state-specific structures. */
	union {
		/** State of the input phase. Used when events=POLLIN. */
		struct {
			/** Buffer for prefix of the query to match with @ref client_query_pfx. */
			char buf[sizeof(client_query_pfx) - 1];
			/**
			 * Length of data currently in the input buffer (@c buf).
			 * If equal to @c sizeof(buf), the prefix has been already matched;
			 * we're waiting for the end of HTTP headers.
			 */
			unsigned len;
		} input;
		/** State of the output phase. Used when events=POLLOUT. */
		struct {
			/**
			 * Offset inside @ref client_response_header.
			 * If equal to @c sizeof(client_response_header), it means
			 * we've already emitted the headers (both HTTP and WAV)
			 * and now we're forwarding PCM audio data.
			 */
			unsigned len;
			/** Offset of our head in ring buffer - @ref alsa_buf. */
			unsigned head;
		} output;
	} x;
} client_t;

enum {
	FD_PIPE,			/**< Pipe - command input. */
	FD_SERVER_SOCKET,	/**< Server socket for accepting streaming connections. */
	FD_ALSA_CAPTURE,	/**< Beginning of the pool of ALSA capture descriptors. */
	FD_MAX = 8			/**< Maximum number of file descriptors to poll. */
};
/**
 * Array of file descriptors to poll.
 *
 * Index            | # Entries | Allocation
 * ---------------- | --------- | ----------
 * FD_PIPE          | 1         | command input
 * FD_SERVER_SOCKET | 1         | server socket
 * FD_ALSA_CAPTURE  | alsa_capture_fds_cnt | ALSA PCM capture fds
 * FD_ALSA_CAPTURE + alsa_capture_fds_cnt | alsa_playback_fds_cnt | ALSA PCM playback fds
 * FD_ALSA_CAPTURE + alsa_capture_fds_cnt + alsa_playback_fds_cnt | until poll_fds_cnt - 1 | client connections
 */
static struct pollfd poll_fds[FD_MAX];
/**
 * Array of client state structures associated with @ref poll_fds.
 *
 * Only entries refering to clients in the @ref poll_fds array are meaningful.
 */
static client_t client[FD_MAX];
/** Number of entries inside @ref poll_fds currently in use. */
static unsigned poll_fds_cnt;
/** Number of entries inside @ref poll_fds used by ALSA capture (starting from index 1). */
static unsigned alsa_capture_fds_cnt;
/** ALSA capture handle, or NULL if no audio capture is currently performed. */
static snd_pcm_t *alsa_capture;
/** Number of channels actually used by audio capture. */
static unsigned alsa_channels;
/** Sample rate actually used by audio capture. */
static unsigned alsa_rate;
/** Number of entries inside @ref poll_fds used by ALSA playback (starting from index @ref FD_ALSA_CAPTURE + @ref alsa_capture_fds_cnt). */
static unsigned alsa_playback_fds_cnt;
/** ALSA playback handle, or NULL if no audio playback is currently performed. */
static snd_pcm_t *alsa_playback;
/** Whether the main loop should stop. */
static unsigned stop;
/** Ring buffer holding captured audio data. */
static char *alsa_buf;
/** Bytes per sample, e.g. 4 in case of 16-bit stereo. */
static unsigned alsa_buf_mul;
/** Size of @ref alsa_buf, in bytes. */
static unsigned alsa_buf_size;
/** Head of @ref alsa_buf ring buffer's queue -- offset in bytes. */
static unsigned alsa_buf_head;
/** Index of a client inside @ref poll_fds which has @c output.head == @ref alsa_buf_head. */
static unsigned slowest_client;
/** Tail of @ref alsa_buf ring buffer's queue -- offset in bytes. */
static unsigned alsa_buf_tail;
/** Headers to send before raw captured audio data; consist of HTTP headers and WAV header. */
static char client_response_header[sizeof(client_response_header_template) - 1 + sizeof(wav_hdr_t)];
/** Timestamp of the last time we've sent keep alive content to the file. */
static time_t last_keep_alive;

/**************************************/

/** Dumps data structure to syslog. */
static void cmd_dump(void)
{
	if (alsa_capture) {
		unsigned size = alsa_buf_tail >= alsa_buf_head ? alsa_buf_tail - alsa_buf_head : alsa_buf_size + alsa_buf_tail - alsa_buf_head;
		syslog(LOG_DEBUG, "audio capture: %u channel%s, %u Hz, %u/%u = %u%% (%u-%u)",
			alsa_channels, alsa_channels == 1 ? "" : "s", alsa_rate, size, alsa_buf_size, size * 100 / alsa_buf_size, alsa_buf_head, alsa_buf_tail);
	} else {
		syslog(LOG_DEBUG, "no audio capture");
	}

	if (config_keep_alive_to && config_keep_alive_what && last_keep_alive) {
		syslog(LOG_DEBUG, "%s sent to %s %lu seconds ago", config_keep_alive_what, config_keep_alive_to, time(NULL) - last_keep_alive);
	}

	for (unsigned i = 0; i < poll_fds_cnt; i++) {
		unsigned is_in = poll_fds[i].events & POLLIN;
		unsigned is_out = poll_fds[i].events & POLLOUT;
		unsigned desc_out = 0;

		const char *desc1 = NULL;
		const char *desc2 = "";
		char desc3[100] = "";

		if (i == FD_PIPE) {
			desc1 = "pipe";
			desc2 = config_pipe;
		} else if (i == FD_SERVER_SOCKET) {
			struct sockaddr_in addr;
			socklen_t len = sizeof(addr);

			desc1 = "socket";
			desc2 = getsockname(poll_fds[i].fd, (struct sockaddr *) &addr, &len) ? NULL : format_addr(&addr);
		} else if (i < FD_ALSA_CAPTURE + alsa_capture_fds_cnt) {
			ASSERT(i >= FD_ALSA_CAPTURE);

			desc1 = "audio capture";
			desc2 = config_dev;
		} else if (i < FD_ALSA_CAPTURE + alsa_capture_fds_cnt + alsa_playback_fds_cnt) {
			ASSERT(i >= FD_ALSA_CAPTURE + alsa_capture_fds_cnt);

			desc1 = "audio playback";
			desc2 = snd_pcm_name(alsa_playback);
			if (i == FD_ALSA_CAPTURE + alsa_capture_fds_cnt)
				desc_out++;
		} else {
			desc1 = "client";
			desc2 = format_addr(&client[i].addr);
			if (is_in) {
				if (client[i].x.input.len < sizeof(client[i].x.input.buf)) {
					snprintf(desc3, sizeof(desc3), ", received %u/%tu B of headers", client[i].x.input.len, sizeof(client[i].x.input.buf));
				} else {
					snprintf(desc3, sizeof(desc3), ", waiting for end of headers");
				}
			} else if (is_out) {
				desc_out++;
			}
		}
		if (desc_out) {
			if (client[i].x.output.len < sizeof(client_response_header)) {
				snprintf(desc3, sizeof(desc3), ", sent %u/%tu B of headers", client[i].x.output.len, sizeof(client_response_header));
			} else {
				unsigned size = alsa_buf_tail >= client[i].x.output.head ? alsa_buf_tail - client[i].x.output.head : alsa_buf_size + alsa_buf_tail - client[i].x.output.head;
				snprintf(desc3, sizeof(desc3), ", sending audio data, uses %u B = %u%% of buffer", size, size * 100 / alsa_buf_size);
			}
		}

		syslog(LOG_DEBUG, "poll[%u]=%d (%s%s%s) is %s%s %s%s",
			i, poll_fds[i].fd,
			is_in ? "IN" : "",
			is_in && is_out ? "|" : "",
			is_out ? "OUT" : "",
			i == slowest_client ? "slowest " : "",
			desc1, desc2, desc3);
	}
}

/**
 * Saves status information to @ref config_status_file.
 *
 * @return Non-zero value if status has been successfully written.
 */
static int save_status(void)
{
	FILE *f;

	if (!config_status_file)
		return 0;

	f = fopen(config_status_file, "w");
	if (f) {
		if (alsa_capture)
			fprintf(f, "capture=%s\n", snd_pcm_name(alsa_capture));
		fprintf(f, "clients=%u\na=%d\nb=%d\nrate=%u\n",
			poll_fds_cnt - (FD_ALSA_CAPTURE + alsa_capture_fds_cnt + alsa_playback_fds_cnt),
			softvol_a256, softvol_b, config_override_rate
		);
		if (alsa_playback)
			fprintf(f, "playback=%s\n", snd_pcm_name(alsa_playback));
		fclose(f);
		return 0;
	} else {
		syslog(LOG_ERR, "writing status to %s: %s", config_status_file, strerror(errno));
	}

	return 1;
}

/** Clips sample to 16 bits signed integer value. */
#define	CLIP_SAMPLE(sample)	do { \
	if ((sample) > 32767) \
		(sample) = 32767; \
	else if ((sample) < -32768) \
		(sample) = -32768; \
} while (0)

/**
 * Processes sound in-place according to software volume control settings.
 *
 * @param pcm Sound frames.
 * @param frames Number of frames in @c pcm.
 * @param channels Number of channels in each frame.
 */
static void process_sound(int16_t *pcm, unsigned frames, unsigned channels)
{
	unsigned len = frames * channels;

	if (softvol_a256 == 256)
		for (; len > 0; len--, pcm++) {
			int sample = (int) *pcm + softvol_b;
			CLIP_SAMPLE(sample);
			*pcm = (int16_t) sample;
		}
	else if (softvol_shl)
		for (; len > 0; len--, pcm++) {
			int sample = ((int) *pcm + softvol_b) << softvol_shl;
			CLIP_SAMPLE(sample);
			*pcm = (int16_t) sample;
		}
	else
		for (; len > 0; len--, pcm++) {
			int sample = (((int) *pcm + softvol_b) * softvol_a256) >> 8;
			CLIP_SAMPLE(sample);
			*pcm = (int16_t) sample;
		}
}

/**
 * Processes sound frames just put into ring buffer.
 *
 * @param frames Number of new frames beyond current ring buffer's tail.
 */
static void process_new_sound_in_ring_buffer(unsigned frames)
{
	unsigned next_tail = alsa_buf_tail + frames * alsa_buf_mul;

	ASSERT(sizeof(int16_t) * alsa_channels == alsa_buf_mul);	// S16_LE

	if (next_tail <= alsa_buf_size) {
		process_sound((int16_t *) (alsa_buf + alsa_buf_tail), frames, alsa_channels);
	} else {
		process_sound((int16_t *) (alsa_buf + alsa_buf_tail), (alsa_buf_size - alsa_buf_tail) / alsa_buf_mul, alsa_channels);
		process_sound((int16_t *) alsa_buf, (next_tail - alsa_buf_size) / alsa_buf_mul, alsa_channels);
	}
}

/**************************************/

/**
 * Gracefully handles signals which kill us.
 *
 * @param signum Signal number.
 */
static void signal_stop(int signum)
{
	syslog(LOG_NOTICE, "got signal %d, quitting", signum);

	stop++;
}

/**
 * Initiates the program.
 */
static void init_program(void)
{
	static const int signums[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM };
	struct sigaction act;
	unsigned i;
	snd_output_t *log;
	snd_output_stdio_attach(&log, stderr, 0);

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
	/*
	// avoid creating zombies when forking and not waiting for children to terminate
	act.sa_flags = SA_NOCLDWAIT;
	sigaction(SIGCHLD, &act, NULL);
	*/

	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_stop;
	for (i = 0; i < sizeof(signums) / sizeof(signums[0]); i++)
		sigaction(signums[i], &act, NULL);
}

/**************************************/

/**
 * Synthesizes headers inside @ref client_response_header.
 *
 * @param rate Sample rate (e.g. 32000).
 * @param sample Sample size in bits (e.g. 16).
 * @param channels Number of audio channels (e.g. 2).
 */
static void synthesize_header(unsigned rate, unsigned sample, unsigned channels)
{
	wav_hdr_t header = {
		.riff = "RIFF",
		.fourcc = "WAVE",
		.fmt_tag = "fmt ",
		.fmt_size = sizeof(header.fmt),
		.data_tag = "data",
	};

	header.fmt.sps = rate;
	header.fmt.sample = sample;
	header.fmt.channels = channels;
	header.fmt.block = header.fmt.sample / 8 * header.fmt.channels;
	header.fmt.bps = header.fmt.sps * header.fmt.block;
	header.data_size = 4 * 60 * 60 * header.fmt.bps;	// 4 hours
	header.riff_size = sizeof(wav_hdr_t) - offsetof(wav_hdr_t, fourcc) + header.data_size;

	header.fmt.tag = htole16(1);
	header.fmt.channels = htole16(header.fmt.channels);
	header.fmt.sps = htole32(header.fmt.sps);
	header.fmt.bps = htole32(header.fmt.bps);
	header.fmt.block = htole16(header.fmt.block);
	header.fmt.sample = htole16(header.fmt.sample);
	header.riff_size = htole32(header.riff_size);
	header.fmt_size = htole32(header.fmt_size);
	header.data_size = htole32(header.data_size);

	memcpy(client_response_header, client_response_header_template, sizeof(client_response_header_template) - 1);
	memcpy(client_response_header + sizeof(client_response_header_template) - 1, &header, sizeof(header));
}

/**************************************/

/**
 * Sends keep alive content to configured file.
 */
static void keep_alive(void)
{
	FILE *f = fopen(config_keep_alive_to, "w");

	if (f) {
		if (fwrite(config_keep_alive_what, strlen(config_keep_alive_what), 1, f) == 1) {
			VERBOSE(syslog(LOG_DEBUG, "keep alive \"%s\" sent to %s", config_keep_alive_what, config_keep_alive_to));
		} else {
			syslog(LOG_WARNING, "keep alive \"%s\" to %s: %s", config_keep_alive_what, config_keep_alive_to, strerror(errno));
		}
		fclose(f);
	} else {
		syslog(LOG_WARNING, "keep alive to %s: %s", config_keep_alive_to, strerror(errno));
	}
}

/**************************************/

/**
 * Stops ALSA capture.
 */
static void alsa_stop_capture(void)
{
	if (!alsa_capture)
		return;

	VERBOSE(syslog(LOG_DEBUG, "stopping capture from %s", config_dev));

	snd_pcm_close(alsa_capture);
	alsa_capture = NULL;
	free(alsa_buf);
	alsa_buf = NULL;
	alsa_buf_size = alsa_buf_head = alsa_buf_tail = 0;
	alsa_buf_mul = 0;
	poll_fds_cnt -= alsa_capture_fds_cnt;
	//ASSERT(poll_fds_cnt == FD_ALSA_CAPTURE);	cannot do that if called as atexit()'s callback
	alsa_capture_fds_cnt = 0;
	slowest_client = 0;
	save_status();
}

/**
 * Moves data structure related to given client to another (now free) place.
 *
 * @param src Index of existing working client.
 * @param dest Index of a hole in data structure (unused entry).
 */
static void client_move(unsigned src, unsigned dest)
{
	VERBOSE(syslog(LOG_DEBUG, "client[%u]->[%u]", src, dest));
	memcpy(poll_fds + dest, poll_fds + src, sizeof(poll_fds[dest]));
	memcpy(client + dest, client + src, sizeof(client[dest]));
}

/**
 * Closes connection to given client.
 *
 * In case this was our only client, stops ALSA capture.
 *
 * @param i Client index inside @ref poll_fds.
 * @return 1 if we moved another client to the given index in our data
 *         structures, 0 otherwise.
 */
static unsigned client_close(unsigned i)
{
	ASSERT(i < poll_fds_cnt);
	ASSERT(i >= FD_ALSA_CAPTURE + alsa_capture_fds_cnt + alsa_playback_fds_cnt);
	VERBOSE(syslog(LOG_DEBUG, "-- client[%u] = %d: %s", i, poll_fds[i].fd, format_addr(&client[i].addr)));
	shutdown(poll_fds[i].fd, SHUT_WR | (poll_fds[i].events == POLLOUT ? 0 : SHUT_RD));
	close(poll_fds[i].fd);
	if (slowest_client == i)
		slowest_client = 0;	// must be fixed by ring_buffer_advance
	poll_fds_cnt--;
	save_status();
	if (i < poll_fds_cnt) {
		client_move(poll_fds_cnt, i);
		return 1;
	}
	if (poll_fds_cnt == FD_ALSA_CAPTURE + alsa_capture_fds_cnt)	// last client closed
		alsa_stop_capture();
	return 0;
}

/**
 * Advances ring buffer's head to a minimum value among active clients (including internal ALSA playback/loopback "client").
 */
static void ring_buffer_advance(void)
{
	int max_len = 0;
	unsigned min_head = alsa_buf_tail;
	unsigned first_in = 0;
	unsigned alsa_playback_i = FD_ALSA_CAPTURE + alsa_capture_fds_cnt;

	slowest_client = 0;
	// enumerate clients
	for (unsigned i = alsa_playback_i; i < poll_fds_cnt; i++) {
		unsigned is_playback = alsa_playback_fds_cnt && i == alsa_playback_i;

		if (is_playback || poll_fds[i].events & POLLOUT) {
			int len = alsa_buf_tail - client[i].x.output.head;

			if (len < 0)
				len += alsa_buf_size;
			if (max_len < len) {
				max_len = 0;
				min_head = client[i].x.output.head;
				slowest_client = i;
			}

			if (is_playback)
				i += alsa_playback_fds_cnt - 1;	// jump over rest of ALSA playback fds
		} else if (poll_fds[i].events & POLLIN) {
			if (!first_in)
				first_in = i;
		}
	}

	if (!slowest_client) {
		slowest_client = first_in;
		if (!slowest_client)
			slowest_client = FD_ALSA_CAPTURE + alsa_capture_fds_cnt;	// anyone
	}

	//VERBOSE(syslog(LOG_DEBUG, "ring buffer advance %u -> %u, tail %u, slowest client[%u]", alsa_buf_head, min_head, alsa_buf_tail, slowest_client));
	alsa_buf_head = min_head;
}

/**
 * Stops playback of captured audio (loopback).
 */
static void alsa_playback_stop(void)
{
	unsigned alsa_playback_i;
	unsigned do_ring_buffer_advance;

	if (!alsa_playback)
		return;

	VERBOSE(syslog(LOG_DEBUG, "stopping playback"));

	snd_pcm_close(alsa_playback);
	alsa_playback = NULL;
	alsa_playback_i = FD_ALSA_CAPTURE + alsa_capture_fds_cnt;
	do_ring_buffer_advance = 0;
	if (slowest_client == alsa_playback_i) {
		slowest_client = 0;	// must be fixed by ring_buffer_advance
		do_ring_buffer_advance++;
	}
	poll_fds_cnt -= alsa_playback_fds_cnt;
	if (alsa_playback_i < poll_fds_cnt) {
		// move remaining clients from beyond new poll_fds_cnt to fds previously occupied by ALSA playback fds
		for (unsigned i = 0; i < alsa_playback_fds_cnt && alsa_playback_i + i < poll_fds_cnt; i++) {
			client_move(poll_fds_cnt + i, alsa_playback_i + i);
			do_ring_buffer_advance++;
		}
		if (do_ring_buffer_advance)
			ring_buffer_advance();
	} else {	// last client closed
		ASSERT(alsa_playback_i == poll_fds_cnt);
		alsa_stop_capture();
	}
	alsa_playback_fds_cnt = 0;
	save_status();
}

/**
 * Perfoms a step of ALSA capture.
 *
 * @return 0 on success.
 */
static int alsa_process_capture(void)
{
	unsigned short revents;
	int rv;
	unsigned len;
	snd_pcm_sframes_t amount;

	ASSERT(alsa_capture);

	revents = 0;
	rv = snd_pcm_poll_descriptors_revents(alsa_capture, poll_fds + FD_ALSA_CAPTURE, alsa_capture_fds_cnt, &revents);

	if (rv) {
		syslog(LOG_WARNING, "ALSA capture poll error: %s", snd_strerror(rv));
		return 1;
	}
	if (!revents)
		return 0;

	len = 0;
	while (!len) {
		len = (alsa_buf_head > alsa_buf_tail ? alsa_buf_head : alsa_buf_size) - alsa_buf_tail;
		if (alsa_buf_tail + len == alsa_buf_head || (!alsa_buf_head && alsa_buf_tail + len == alsa_buf_size))
			len -= alsa_buf_mul;	// cannot make tail==head, it would mean the buf is empty
		if (!len) {
			if (!slowest_client) {
				syslog(LOG_NOTICE, "buffer overflow (%u-%u/%u)",
					alsa_buf_head, alsa_buf_tail, alsa_buf_size);
				return 2;
			}
			if (slowest_client == FD_ALSA_CAPTURE + alsa_capture_fds_cnt) {
				VERBOSE(syslog(LOG_DEBUG, "buffer overflow (%u-%u/%u) - loopback[%u]",
					alsa_buf_head, alsa_buf_tail, alsa_buf_size, slowest_client));
				//alsa_playback_stop();
				client[slowest_client].x.output.head = alsa_buf_tail;
			} else {
				VERBOSE(syslog(LOG_NOTICE, "buffer overflow (%u-%u/%u) - closing slowest client[%u]: %s",
					alsa_buf_head, alsa_buf_tail, alsa_buf_size, slowest_client,
					format_addr(&client[slowest_client].addr)));
				ASSERT(slowest_client >= FD_ALSA_CAPTURE + alsa_capture_fds_cnt + alsa_playback_fds_cnt);
				client_close(slowest_client);
			}
			// was it last client?
			if (!alsa_capture)
				return 0;
			ring_buffer_advance();
		}
	}

	amount = snd_pcm_readi(alsa_capture, alsa_buf + alsa_buf_tail, len / alsa_buf_mul);
	if (amount == -EPIPE) {
		syslog(LOG_DEBUG, "ALSA capture: recovering from %s", snd_strerror(amount));
		amount = snd_pcm_recover(alsa_capture, amount, 0);
	}
	if (amount < 0) {
		syslog(LOG_WARNING, "ALSA capture: %s", snd_strerror(amount));
		return 1;
	}
	if (!amount)
		return 0;

	if (softvol_a256 != 256 || softvol_b)
		process_new_sound_in_ring_buffer(amount);
	alsa_buf_tail += amount * alsa_buf_mul;
	ASSERT(alsa_buf_tail <= alsa_buf_size);
	if (alsa_buf_tail == alsa_buf_size)
		alsa_buf_tail = 0;

	return 0;
}

/**
 * Starts ALSA capture.
 *
 * @return 0 on success.
 */
static int alsa_start_capture(void)
{
	int err;

	if (alsa_capture)
		return 0;

	ASSERT(!alsa_capture_fds_cnt);
	ASSERT(poll_fds_cnt == FD_ALSA_CAPTURE);
	ASSERT(!slowest_client);
	ASSERT(!alsa_buf);

	VERBOSE(syslog(LOG_DEBUG, "ALSA capture: starting %s", config_dev));

	err = snd_pcm_open(&alsa_capture, config_dev, SND_PCM_STREAM_CAPTURE, SND_PCM_NONBLOCK);
	if (err) {
		syslog(LOG_ERR, "ALSA capture: unable to open %s: %s", config_dev, snd_strerror(err));
		return 1;
	}

	do {
		snd_pcm_uframes_t buffer_size, period_size;

		if (alsa_set_hwparams(alsa_capture, config_capture_buffer, config_capture_period, 0, 0, &alsa_channels, &alsa_rate, &buffer_size, &period_size))
			break;
		VERBOSE(syslog(LOG_DEBUG, "ALSA capture: ch#=%u rate=%u buf=%lu per=%lu", alsa_channels, alsa_rate, buffer_size, period_size));
		if (config_override_rate) {
			VERBOSE(syslog(LOG_DEBUG, "ALSA capture: overriding sample rate from %u to %u", alsa_rate, config_override_rate));
			alsa_rate = config_override_rate;
		}

		if (alsa_set_swparams(alsa_capture, buffer_size, period_size))
			break;

		err = snd_pcm_start(alsa_capture);
		if (err) {
			syslog(LOG_ERR, "ALSA capture: unable to start %s: %s", config_dev, snd_strerror(err));
			break;
		}

		synthesize_header(alsa_rate, 16, alsa_channels);	// SND_PCM_FORMAT_S16_LE

		alsa_capture_fds_cnt = snd_pcm_poll_descriptors(alsa_capture, poll_fds + poll_fds_cnt, FD_MAX - poll_fds_cnt);
		poll_fds_cnt += alsa_capture_fds_cnt;
		alsa_buf_mul = snd_pcm_frames_to_bytes(alsa_capture, 1);
		alsa_buf_size = buffer_size * alsa_buf_mul * config_buf_mul;
		alsa_buf_head = alsa_buf_tail = 0;
		alsa_buf = malloc(alsa_buf_size);
		save_status();
		return 0;
	} while (0);

	alsa_stop_capture();
	return 2;
}

/**************************************/

/**
 * Accepts connection from a new client.
 *
 * In case this is our first client, starts ALSA capture.
 *
 * @param accept_sock File descriptor of our listening socket.
 * @return 0 on success (= the program can continue working).
 */
static int client_process_accept(int accept_sock)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int sock = accept(accept_sock, (struct sockaddr *) &addr, &len);

	if (sock >= 0) {
		do {
			if (setnonblock(sock))
				break;

			if (poll_fds_cnt >= FD_MAX) {
				static const char error_503[] = "HTTP/1.0 503 Too Many Connections\n\n";

				VERBOSE(syslog(LOG_DEBUG, "connection from %s denied", format_addr(&addr)));
				if (send(sock, error_503, sizeof(error_503) - 1, 0) < 0)
					syslog(LOG_WARNING, "send 503: %s", strerror(errno));
				shutdown(sock, SHUT_RD|SHUT_WR);
				close(sock);
				return 0;
			}

			if (!alsa_capture) {
				if (alsa_start_capture())
					break;
				slowest_client = poll_fds_cnt;
			}

			VERBOSE(syslog(LOG_DEBUG, "++ client[%u] = %d: %s", poll_fds_cnt, sock, format_addr(&addr)));

			poll_fds[poll_fds_cnt].fd = sock;
			poll_fds[poll_fds_cnt].events = POLLIN;
			memset(client + poll_fds_cnt, 0, sizeof(client[poll_fds_cnt]));	// init client state
			memcpy(&client[poll_fds_cnt].addr, &addr, sizeof(addr));
			poll_fds_cnt++;
			save_status();
			return 0;
		} while (0);

		close(sock);
	}

	syslog(LOG_ERR, "accept: %s", strerror(errno));
	return 1;
}

/**
 * Receives input from given client.
 *
 * @param i Client index inside @ref poll_fds.
 * @return 0 if connection to that client is fine, non-zero if it should be closed.
 */
static int client_process_input(unsigned i)
{
	int last;
	ssize_t amount;

	ASSERT(poll_fds[i].fd > 0);

	if (client[i].x.input.len < sizeof(client[i].x.input.buf)) {
		// phase 1: read query
		last = 0;
		amount = recv(poll_fds[i].fd, client[i].x.input.buf + client[i].x.input.len, sizeof(client[i].x.input.buf) - client[i].x.input.len, 0);
	} else {
		// phase 2: wait for double new line (end of HTTP request headers)
		last = client[i].x.input.buf[0];
		amount = recv(poll_fds[i].fd, client[i].x.input.buf, sizeof(client[i].x.input.buf), 0);
	}
	if (amount < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		syslog(LOG_WARNING, "client[%u]=%s input: %s", i, format_addr(&client[i].addr), strerror(errno));
		return -1;
	}
	if (!amount)
		return 1;	// EOF
	if (client[i].x.input.len < sizeof(client[i].x.input.buf)) {
		// phase 1
		client[i].x.input.len += amount;
		if (memcmp(client[i].x.input.buf, client_query_pfx, client[i].x.input.len)) {
			syslog(LOG_NOTICE, "client[%u]=%s sent unknown query: %.*s", i, format_addr(&client[i].addr), client[i].x.input.len, client[i].x.input.buf);
			return -2;
		}
		if (client[i].x.input.len == sizeof(client[i].x.input.buf)) {
			// enter phase 2 - and process the same data
			VERBOSE(syslog(LOG_DEBUG, "client[%u]=%s sent valid query", i, format_addr(&client[i].addr)));
			amount = client[i].x.input.len;
		}
	}
	if (client[i].x.input.len == sizeof(client[i].x.input.buf)) {
		// phase 2
		ssize_t j;

		for (j = 0; j < amount; j++) {
			int c = client[i].x.input.buf[j];

			switch (c) {
				case '\r':
					break;
				case '\n':
					if (last == '\n') {
						// gotcha, enter phase 3 (output)
						VERBOSE(syslog(LOG_DEBUG, "client[%u]=%s finished sending headers", i, format_addr(&client[i].addr)));
						shutdown(poll_fds[i].fd, SHUT_RD);
						poll_fds[i].events = POLLOUT;	// next time handle_client_output will be called instead
						client[i].x.output.len = 0;
						client[i].x.output.head = alsa_buf_head;
						return 0;	// !!!
					}
					// fallthrough
				default:
					last = c;
					break;
			}
		}

		client[i].x.input.buf[0] = last;
	}

	return 0;
}

/**
 * Sends output to given client.
 *
 * @param i Client index inside @ref poll_fds.
 * @return 0 if connection to that client is fine, non-zero if it should be closed.
 */
static int client_process_output(unsigned i)
{
	ssize_t amount = -1;

	ASSERT(poll_fds[i].fd > 0);

	if (client[i].x.output.len < sizeof(client_response_header)) {
		// phase 1: send header
		amount = send(poll_fds[i].fd, client_response_header + client[i].x.output.len, sizeof(client_response_header) - client[i].x.output.len, 0);
	} else {
		// phase 2: send audio data
		ASSERT(client[i].x.output.head != alsa_buf_tail);
		amount = send(poll_fds[i].fd,
			alsa_buf + client[i].x.output.head,
			(client[i].x.output.head > alsa_buf_tail ? alsa_buf_size : alsa_buf_tail) - client[i].x.output.head,
			0);
	}

	if (amount < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		if (errno == EPIPE || errno == ECONNRESET) {
			VERBOSE(syslog(LOG_DEBUG, "client[%u]=%s output: %s", i, format_addr(&client[i].addr), strerror(errno)));
		} else {
			syslog(LOG_WARNING, "client[%u]=%s output: %s", i, format_addr(&client[i].addr), strerror(errno));
		}
		return -1;
	}
	if (!amount)
		return 1;	// EOF

	if (client[i].x.output.len < sizeof(client_response_header)) {
		client[i].x.output.len += amount;
	} else {
		client[i].x.output.head += amount;
		if (client[i].x.output.head == alsa_buf_size)
			client[i].x.output.head = 0;
	}

	return 0;
}

/**************************************/

/**
 * Starts playback of captured audio (loopback).
 *
 * @param device Name of ALSA playback device.
 */
static void alsa_playback_start(const char *device)
{
	unsigned max_loop = 1;
	char *buf = NULL;

	alsa_playback_stop();
	VERBOSE(syslog(LOG_DEBUG, "ALSA playback: starting %s", device));
	ASSERT(!alsa_playback_fds_cnt);

	for (unsigned loop = 0; loop < max_loop; loop++) {
		int err = snd_pcm_open(&alsa_playback, device, SND_PCM_STREAM_PLAYBACK, SND_PCM_NONBLOCK);
		if (err) {
			syslog(LOG_ERR, "ALSA playback: unable to open %s: %s", device, snd_strerror(err));
			return;
		}

		do {
			unsigned channels, rate;
			snd_pcm_uframes_t buffer_size, period_size;
			unsigned alsa_playback_i;

			if (!alsa_capture) {
				if (alsa_start_capture())
					break;
				slowest_client = poll_fds_cnt;
			}

			err = alsa_set_hwparams(alsa_playback, config_playback_buffer, config_playback_period, alsa_channels, alsa_rate, &channels, &rate, &buffer_size, &period_size);
			if (err) {
				if (!buf && config_auto_prefix_inval && err == -EINVAL) {
					size_t pfx_len = strlen(config_auto_prefix_inval);
					size_t suf_len = strlen(device) + 1;
					buf = malloc(pfx_len + suf_len);
					memcpy(buf, config_auto_prefix_inval, pfx_len);
					memcpy(buf + pfx_len, device, suf_len);
					device = buf;
					max_loop = 2;
				}
				break;
			}
			VERBOSE(syslog(LOG_DEBUG, "ALSA playback: device=%s ch#=%u rate=%u buf=%lu per=%lu", device, channels, rate, buffer_size, period_size));

			if (alsa_set_swparams(alsa_playback, buffer_size, period_size))
				break;

			alsa_playback_fds_cnt = snd_pcm_poll_descriptors_count(alsa_playback);
			if (alsa_playback_fds_cnt > FD_MAX - poll_fds_cnt) {
				syslog(LOG_WARNING, "ALSA playback: too many clients, no space for %u fds", alsa_playback_fds_cnt);
				alsa_playback_fds_cnt = 0;
				break;
			}
			alsa_playback_i = FD_ALSA_CAPTURE + alsa_capture_fds_cnt;	// index of our "client" - already in "data output" phase (no input, no header)
			if (alsa_playback_i < poll_fds_cnt)
				// make space for that many descriptors
				for (unsigned i = 0; i < alsa_playback_fds_cnt; i++)
					client_move(alsa_playback_i + i, poll_fds_cnt + i);
			poll_fds_cnt += alsa_playback_fds_cnt;
			snd_pcm_poll_descriptors(alsa_playback, poll_fds + alsa_playback_i, alsa_playback_fds_cnt);
			//for (unsigned i = 0; i < alsa_playback_fds_cnt; i++)
			//	poll_fds[alsa_playback_i + i].revents = 0;
			client[alsa_playback_i].x.output.len = sizeof(client_response_header);
			client[alsa_playback_i].x.output.head = alsa_buf_head;
			free(buf);
			save_status();
			return;
		} while (0);

		alsa_playback_stop();
	}

	free(buf);
}

/**
 * Perfoms a step of ALSA playback.
 *
 * @return 0 on success.
 */
static int alsa_process_playback(void)
{
	unsigned short revents;
	unsigned i;
	int rv;
	unsigned len;
	snd_pcm_sframes_t amount;

	ASSERT(alsa_playback);
	ASSERT(alsa_playback_fds_cnt);

	revents = 0;
	i = FD_ALSA_CAPTURE + alsa_capture_fds_cnt;
	rv = snd_pcm_poll_descriptors_revents(alsa_playback, poll_fds + i, alsa_playback_fds_cnt, &revents);

	if (rv) {
		syslog(LOG_WARNING, "ALSA playback %s polling failed: %s", snd_pcm_name(alsa_playback), snd_strerror(rv));
		return 1;
	}
	if (!revents)
		return 0;

	ASSERT(client[i].x.output.head != alsa_buf_tail);
	len = (client[i].x.output.head > alsa_buf_tail ? alsa_buf_size : alsa_buf_tail) - client[i].x.output.head;
	amount = snd_pcm_writei(alsa_playback, alsa_buf + client[i].x.output.head, len / alsa_buf_mul);
	if (amount == -EPIPE) {
		syslog(LOG_DEBUG, "ALSA playback: recovering %s from %s", snd_pcm_name(alsa_playback), snd_strerror(amount));
		amount = snd_pcm_recover(alsa_playback, amount, 0);
	}
	if (amount < 0) {
		syslog(LOG_WARNING, "ALSA playback %s failed: %s", snd_pcm_name(alsa_playback), snd_strerror(amount));
		return 1;
	}
	if (!amount)
		return 0;

	client[i].x.output.head += amount * alsa_buf_mul;
	if (client[i].x.output.head == alsa_buf_size)
		client[i].x.output.head = 0;
	return 0;
}

/**************************************/

/** Checks if given input is equal to a command. */
#define	CMD_IS(input, len, cmd)	((len) == sizeof(cmd) - 1 && !memcmp((input), (cmd), (len)))

static const char pipecmd_quit[] = "quit";	/**< Command used to quit. */
static const char pipecmd_dump[] = "dump";	/**< Command for dumping data structure. */
static const char pipecmd_play[] = "play";	/**< Command to start loopback playback. */
static const char pipecmd_stop[] = "stop";	/**< Command to stop loopback playback. */
static const char pipecmd_vol[] = "vol";	/**< Command which changes software volume control settings. */
static const char pipecmd_rate[] = "rate";	/**< Command which sets up fake sample rate. */
static const char pipecmd_verbose[] = "verbose";	/**< Command to control verbosity in syslog. */

/**
 * Reads a command line from pipe and processes it.
 *
 * @param fd File descriptor of the read end of our pipe.
 * @return 0 on success, non-zero if the descriptor must be closed (non-fatal error; program can continue).
 */
static int pipe_process_command(int fd)
{
	static char buf[PIPE_BUF + 1];	// PIPE_BUF is guaranteed to be received in one shot
	ssize_t amount = read(fd, buf, sizeof(buf) - 1);	// leave space for terminating nul char
	char *p;
	size_t len;

	// we went here because select told us that fd is ready for reading; no data available means error
	if (amount <= 0) {
		if (amount < 0)
			syslog(LOG_ERR, "reading from %s: %s", config_pipe, strerror(errno));
		return 1;
	}

	// trim at newline, if any
	for (p = buf + amount; p > buf; p--)
		if (p[-1] != '\n')
			break;
	// put nul at the end
	*p = 0;

	// divide buf into command and arguments (optionaL)
	p = strchr(buf, ' ');
	len = p ? (size_t) (p++ - buf) : strlen(buf);
	VERBOSE(syslog(LOG_DEBUG, "got command from pipe: %.*s %s", (int) len, buf, p));

	if (CMD_IS(buf, len, pipecmd_quit)) {
		signal_stop(-1);
	} else if (CMD_IS(buf, len, pipecmd_dump)) {
		cmd_dump();
	} else if (CMD_IS(buf, len, pipecmd_stop)) {
		alsa_playback_stop();
	} else if (CMD_IS(buf, len, pipecmd_play)) {
		if (p)
			alsa_playback_start(p);
		else
			syslog(LOG_WARNING, "usage: %s <ALSA playback dev>", buf);
	} else if (CMD_IS(buf, len, pipecmd_vol)) {
		if (!p || parse_softvol(p, &softvol_a256, &softvol_b, &softvol_shl))
			syslog(LOG_WARNING, "usage: %s a*256[{+|-}b] (A'=(A+b)*a/256) e.g. %s 512-8192", buf, buf);
		save_status();
	} else if (CMD_IS(buf, len, pipecmd_rate)) {
		if (!p)
			config_override_rate = 0;
		else if (sscanf(p, "%u", &config_override_rate) != 1)
			syslog(LOG_WARNING, "usage: %s [rate] e.g. %s 30000", buf, buf);
		save_status();
	} else if (CMD_IS(buf, len, pipecmd_verbose)) {
		if (!p)
			syslog(LOG_INFO, "verbose: %u", config_verbose);
		else if (sscanf(p, "%u", &config_verbose) != 1)
			syslog(LOG_WARNING, "usage: %s [0|1] e.g. %s 1", buf, buf);
	} else {
		syslog(LOG_WARNING, "ignoring unknown command \"%s\" from %s", buf, config_pipe);
	}

	return 0;
}

/**************************************/

/**
 * Cleans up at program exit.
 */
static void cleanup(void)
{
	remove(config_pipe);
	alsa_stop_capture();
}

/**************************************/

/**
 * Main loop.
 *
 * @param argc Number of command line arguments.
 * @param argv Array of command line arguments.
 * @return 0 on success.
 */
int main(int argc, char **argv)
{
	const char *name = preinit_program(*argv);
	if (configure(name, argc, argv))
		return 1;
	openlog(name, LOG_CONS | LOG_PID | (config_verbose ? LOG_PERROR : 0), LOG_DAEMON);
	if (config_play_info)
		return save_info(0);
	init_program();
	if (init_pipe(config_pipe))
		return 2;
	atexit(cleanup);
	ASSERT(poll_fds_cnt == FD_PIPE);
	poll_fds[poll_fds_cnt].fd = -1;	// reserved for pipe
	poll_fds[poll_fds_cnt].events = POLLIN;
	poll_fds_cnt++;
	ASSERT(poll_fds_cnt == FD_SERVER_SOCKET);
	poll_fds[poll_fds_cnt].fd = create_server_socket();
	if (poll_fds[poll_fds_cnt].fd < 0)
		return 3;
	poll_fds[poll_fds_cnt].events = POLLIN;
	poll_fds_cnt++;
	save_status();

	while (!stop) {
		unsigned i;
		unsigned poll_playback;
		unsigned poll_clients;
		int timeout;
		time_t now = time(NULL);
		unsigned poll_fds_cnt_limit;
		int rv;
		unsigned do_ring_buffer_advance;

		ASSERT(poll_fds_cnt >= FD_ALSA_CAPTURE);

		// pipe
		if (poll_fds[FD_PIPE].fd < 0) {
			poll_fds[FD_PIPE].fd = open(config_pipe, O_RDONLY|O_NONBLOCK);
			if (poll_fds[FD_PIPE].fd < 0) {
				syslog(LOG_ERR, "opening %s: %s", config_pipe, strerror(errno));
				break;
			} else {
				VERBOSE(syslog(LOG_DEBUG, "opened pipe %d at %s", poll_fds[FD_PIPE].fd, config_pipe));
			}
		}

		// alsa playback
		i = FD_ALSA_CAPTURE + alsa_capture_fds_cnt;
		if (alsa_playback_fds_cnt) {
			unsigned no_output = (client[i].x.output.len >= sizeof(client_response_header))
				&& (client[i].x.output.head == alsa_buf_tail);
			poll_playback = !no_output;

			for (; i < FD_ALSA_CAPTURE + alsa_capture_fds_cnt + alsa_playback_fds_cnt; i++) {
				if (no_output != (poll_fds[i].fd < 0))
					poll_fds[i].fd = -poll_fds[i].fd;
			}
		} else {
			poll_playback = 0;
		}

		// clients (excluding alsa playback)
		for (poll_clients = 0/*i = FD_ALSA_CAPTURE + alsa_capture_fds_cnt + alsa_playback_fds_cnt*/; i < poll_fds_cnt; i++) {
			if (poll_fds[i].events & POLLIN) {
				poll_clients++;
			} else if (poll_fds[i].events & POLLOUT) {
				unsigned no_output = (client[i].x.output.len >= sizeof(client_response_header))
						&& (client[i].x.output.head == alsa_buf_tail);

				if (!no_output)
					poll_clients++;

				if (no_output != (poll_fds[i].fd < 0))
					poll_fds[i].fd = -poll_fds[i].fd;
			}
		}

		// alsa capture
		/*
		if (alsa_capture_fds_cnt) {
			int fds_cnt = snd_pcm_poll_descriptors(alsa_capture, poll_fds + FD_ALSA_CAPTURE, alsa_capture_fds_cnt);

			ASSERT(fds_cnt == (int) alsa_capture_fds_cnt);
		}
		*/

		if (alsa_capture && config_keep_alive_to && config_keep_alive_what) {
			timeout = last_keep_alive + (time_t) config_keep_alive_period - now;
			if (timeout < 0)
				timeout = 0;
			else if ((unsigned) timeout > config_keep_alive_period)
				timeout = config_keep_alive_period;
			timeout *= 1000;
		} else {
			timeout = -1;
		}
		if (poll_clients) {
			poll_fds_cnt_limit = poll_fds_cnt;
		} else {
			poll_fds_cnt_limit = FD_ALSA_CAPTURE + alsa_capture_fds_cnt;
			if (poll_playback)
				poll_fds_cnt_limit += alsa_playback_fds_cnt;
		}
		rv = poll(poll_fds, poll_fds_cnt_limit, timeout);

		// error?
		if (rv < 0) {
			if (errno != EINTR)
				syslog(LOG_ERR, "poll: %s", strerror(errno));
			break;
		}

		// timeout?
		if (!rv) {
			keep_alive();
			last_keep_alive = now;
			continue;
		}

		do_ring_buffer_advance = 0;

		// alsa playback
		if (poll_playback) {
			if (alsa_process_playback())
				alsa_playback_stop();
			else
				do_ring_buffer_advance++;
		}

		// clients
		if (poll_clients) {
			for (i = FD_ALSA_CAPTURE + alsa_capture_fds_cnt + alsa_playback_fds_cnt; i < poll_fds_cnt; i++) {
				int rv = 0;

				if (poll_fds[i].revents & POLLIN)
					rv = client_process_input(i);
				else if (poll_fds[i].revents & POLLOUT) {
					rv = client_process_output(i);
					do_ring_buffer_advance++;
				}

				if (rv) {
					i -= client_close(i);
					do_ring_buffer_advance++;
				}
			}
		}

		if (do_ring_buffer_advance && alsa_capture)
			ring_buffer_advance();

		// alsa capture
		if (alsa_capture_fds_cnt) {
			ASSERT(slowest_client);
			if (alsa_process_capture())
				break;
		}

		// accept connections
		if (poll_fds[FD_SERVER_SOCKET].revents)
			if (client_process_accept(poll_fds[FD_SERVER_SOCKET].fd))
				break;

		// pipe command
		if (poll_fds[FD_PIPE].revents) {
			if (pipe_process_command(poll_fds[FD_PIPE].fd)) {
				close(poll_fds[FD_PIPE].fd);
				poll_fds[FD_PIPE].fd = -1;
			}
		}
	}

	return 0;
}

/**
 * @}
 */
