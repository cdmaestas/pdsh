/*****************************************************************************\
 *  reachable.c - preflight reachability check misc module
 *****************************************************************************
 *  Copyright (C) 2026 Chris Maestas.
 *  Written by Chris Maestas.
 *
 *  This file is part of Pdsh, a parallel remote shell program.
 *  For details, see <http://www.llnl.gov/linux/pdsh/>.
 *
 *  Pdsh is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  Pdsh is distributed in the hope that it will be useful, but WITHOUT ANY
 *  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 *  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 *  details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with Pdsh; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
\*****************************************************************************
 *
 *  Modeled on IBM Spectrum Scale's mmdsh(8) "-v" / "-R" behavior: before
 *  the working collective is handed off to the rcmd module, probe each
 *  target once and drop the ones that don't answer, optionally recording
 *  the dropped hosts to a report file.
 *
 *  Probes run in batches of up to opt->fanout hosts at a time (the same
 *  knob pdsh already uses to bound remote command concurrency), each
 *  batch bounded by a shared wall-clock deadline rather than a per-host
 *  serial sleep, so N hosts cost roughly one timeout period, not N.
 *
 *  Probe method is chosen from the active rcmd module (opt->rcmd_name),
 *  since ICMP and "can pdsh actually reach this host" are not the same
 *  question:
 *    - rcmd/ssh:  a non-blocking TCP connect to the ssh port (-o to
 *                 override, default 22). ICMP is routinely filtered by
 *                 firewalls/security groups even when the ssh port is
 *                 open, so pinging first would drop hosts pdsh could
 *                 have reached fine - the TCP check answers the actual
 *                 question ssh cares about.
 *    - rcmd/exec: skipped outright. "exec" never leaves the local host,
 *                 so there is no remote endpoint to be unreachable.
 *    - anything else (rsh, mrsh, krb4, xcpu, ...): falls back to
 *                 shelling out to ping(1), since there's no single
 *                 well-known TCP port to assume for those.
\*****************************************************************************/
#if HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>

#include "src/common/hostlist.h"
#include "src/common/err.h"
#include "src/common/xmalloc.h"
#include "src/pdsh/mod.h"

#ifndef PING_PATH
#  define PING_PATH "/sbin/ping"
#endif

/* Default per-batch probe budget; overridable with -W. */
#define REACHABLE_DEFAULT_TIMEOUT_SECS  2

/* Used when opt->fanout is unset/non-positive by the time we run. */
#define REACHABLE_DEFAULT_CONCURRENCY   32

/* Default TCP port probed for the ssh rcmd module; overridable with -o. */
#define REACHABLE_DEFAULT_SSH_PORT      22

#if STATIC_MODULES
#  define pdsh_module_info reachable_module_info
#  define pdsh_module_priority reachable_module_priority
#endif

int pdsh_module_priority = 110;

struct probe {
    pid_t  pid;       /* icmp method: child pid running ping           */
    int    fd;        /* tcp method:  in-progress connect() socket     */
    char  *host;
    int    reachable;  /* -1 = pending, 0 = no, 1 = yes */
};

static int reachable_opt_v(opt_t *, int, char *);
static int reachable_opt_U(opt_t *, int, char *);
static int reachable_opt_W(opt_t *, int, char *);
static int reachable_opt_o(opt_t *, int, char *);
static int mod_reachable_postop(opt_t *opt);
static void filter_unreachable_hosts(opt_t *opt);
static void run_icmp_probe_batch(struct probe *batch, int n);
static void run_tcp_probe_batch(struct probe *batch, int n, int port);
static void write_report_file(hostlist_t unreachable);

static bool  verify       = false;
static char *report_file  = NULL;
static int   timeout_secs = REACHABLE_DEFAULT_TIMEOUT_SECS;
static int   tcp_port     = REACHABLE_DEFAULT_SSH_PORT;

/*
 * Export pdsh module operations structure
 */
struct pdsh_module_operations reachable_module_ops = {
    (ModInitF)       NULL,
    (ModExitF)       NULL,
    (ModReadWcollF)  NULL,
    (ModPostOpF)     mod_reachable_postop
};

/*
 * This module provides no rcmd connect method of its own.
 */
struct pdsh_rcmd_operations reachable_rcmd_ops = {
    (RcmdInitF)  NULL,
    (RcmdSigF)   NULL,
    (RcmdF)      NULL,
};

/*
 * Export module options
 */
struct pdsh_module_option reachable_module_options[] =
 { { 'v', NULL, "exclude unreachable targets before running (mmdsh -v)",
     DSH | PCP, (optFunc) reachable_opt_v
   },
   { 'U', "file", "write excluded (unreachable) hosts to file, requires -v",
     DSH | PCP, (optFunc) reachable_opt_U
   },
   { 'W', "seconds", "preflight probe timeout, default 2s, requires -v",
     DSH | PCP, (optFunc) reachable_opt_W
   },
   { 'o', "port", "ssh port to probe for -R ssh, default 22, requires -v",
     DSH | PCP, (optFunc) reachable_opt_o
   },
   PDSH_OPT_TABLE_END
 };

/*
 * Reachable module info
 */
struct pdsh_module pdsh_module_info = {
  "misc",
  "reachable",
  "Chris Maestas",
  "mmdsh-style preflight reachability check before fanning out",
  DSH | PCP,

  &reachable_module_ops,
  &reachable_rcmd_ops,
  &reachable_module_options[0],
};

static int reachable_opt_v(opt_t *pdsh_opt, int opt, char *arg)
{
    verify = true;
    return 0;
}

static int reachable_opt_U(opt_t *pdsh_opt, int opt, char *arg)
{
    report_file = Strdup(arg);
    return 0;
}

static int reachable_opt_W(opt_t *pdsh_opt, int opt, char *arg)
{
    char *end;
    long  val = strtol(arg, &end, 10);

    if (*end != '\0' || val <= 0)
        errx("%p: invalid setting \"%s\" for -W\n", arg);

    timeout_secs = (int) val;
    return 0;
}

static int reachable_opt_o(opt_t *pdsh_opt, int opt, char *arg)
{
    char *end;
    long  val = strtol(arg, &end, 10);

    if (*end != '\0' || val <= 0 || val > 65535)
        errx("%p: invalid setting \"%s\" for -o\n", arg);

    tcp_port = (int) val;
    return 0;
}

static int mod_reachable_postop(opt_t *opt)
{
    bool non_default_opts = report_file
        || timeout_secs != REACHABLE_DEFAULT_TIMEOUT_SECS
        || tcp_port     != REACHABLE_DEFAULT_SSH_PORT;

    if (!verify && non_default_opts)
        errx("%p: -U/-W/-o require -v\n");

    if (!verify || !opt->wcoll)
        return 0;

    if (opt->rcmd_name && strcmp(opt->rcmd_name, "exec") == 0) {
        err("%p: reachable: -R exec never leaves the local host, "
            "skipping preflight check\n");
        return 0;
    }

    filter_unreachable_hosts(opt);

    return 0;
}

/*
 *  Fork up to `n' concurrent "ping -c 1 host" children and wait on all
 *    of them against a single shared deadline (timeout_secs from the
 *    time the batch is launched), rather than per-host serial waits.
 *    Anything still outstanding when the deadline passes is killed and
 *    counted as unreachable.
 */
static void run_icmp_probe_batch(struct probe *batch, int n)
{
    int i, remaining = 0;
    struct timeval start, now;
    long elapsed_ms;

    for (i = 0; i < n; i++) {
        pid_t pid = fork();

        batch[i].reachable = -1;

        if (pid < 0) {
            err("%p: reachable: fork: %m\n");
            batch[i].pid = -1;
            batch[i].reachable = 1; /* fail open - don't drop on our error */
            continue;
        }

        if (pid == 0) {
            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
            }
            execl(PING_PATH, PING_PATH, "-c", "1", batch[i].host, (char *) NULL);
            _exit(127);
        }

        batch[i].pid = pid;
        remaining++;
    }

    gettimeofday(&start, NULL);
    while (remaining > 0) {
        for (i = 0; i < n; i++) {
            int status;

            if (batch[i].reachable != -1)
                continue;

            if (waitpid(batch[i].pid, &status, WNOHANG) == batch[i].pid) {
                batch[i].reachable =
                    (WIFEXITED(status) && WEXITSTATUS(status) == 0);
                remaining--;
            }
        }

        if (remaining == 0)
            break;

        gettimeofday(&now, NULL);
        elapsed_ms = (now.tv_sec  - start.tv_sec)  * 1000 +
                     (now.tv_usec - start.tv_usec) / 1000;
        if (elapsed_ms >= (long) timeout_secs * 1000)
            break;

        usleep(50000); /* 50ms poll interval */
    }

    /* Anything still pending timed out - kill and reap it. */
    for (i = 0; i < n; i++) {
        int status;

        if (batch[i].reachable == -1) {
            kill(batch[i].pid, SIGKILL);
            waitpid(batch[i].pid, &status, 0);
            batch[i].reachable = 0;
        }
    }
}

/*
 *  Open up to `n' concurrent non-blocking TCP connect()s to `port' and
 *    poll() all of them against a single shared deadline. This answers
 *    "can pdsh actually reach sshd here" directly, without depending on
 *    ICMP being permitted along the path.
 */
static void run_tcp_probe_batch(struct probe *batch, int n, int port)
{
    struct pollfd *pfds = Malloc(n * sizeof(*pfds));
    int  *idx  = Malloc(n * sizeof(*idx));
    int   i, remaining = 0;
    struct timeval start, now;
    char  portstr[8];

    snprintf(portstr, sizeof(portstr), "%d", port);

    for (i = 0; i < n; i++) {
        struct addrinfo hints, *res = NULL;
        int fd, flags;

        batch[i].reachable = -1;
        batch[i].fd = -1;

        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(batch[i].host, portstr, &hints, &res) != 0 || !res) {
            batch[i].reachable = 0; /* can't resolve -> treat as unreachable */
            continue;
        }

        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) {
            freeaddrinfo(res);
            batch[i].reachable = 1; /* fail open on local resource error */
            continue;
        }

        flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0 && errno != EINPROGRESS) {
            close(fd);
            freeaddrinfo(res);
            batch[i].reachable = 0;
            continue;
        }

        freeaddrinfo(res);
        batch[i].fd = fd;
        remaining++;
    }

    gettimeofday(&start, NULL);
    while (remaining > 0) {
        int nfds = 0;
        long elapsed_ms, remaining_ms;
        int rc, k;

        for (i = 0; i < n; i++) {
            if (batch[i].fd >= 0 && batch[i].reachable == -1) {
                pfds[nfds].fd      = batch[i].fd;
                pfds[nfds].events  = POLLOUT;
                pfds[nfds].revents = 0;
                idx[nfds] = i;
                nfds++;
            }
        }

        if (nfds == 0)
            break;

        gettimeofday(&now, NULL);
        elapsed_ms = (now.tv_sec  - start.tv_sec)  * 1000 +
                     (now.tv_usec - start.tv_usec) / 1000;
        remaining_ms = (long) timeout_secs * 1000 - elapsed_ms;
        if (remaining_ms <= 0)
            break;

        rc = poll(pfds, nfds, remaining_ms > INT_MAX ? INT_MAX : (int) remaining_ms);
        if (rc <= 0)
            break; /* timed out, or interrupted - leftovers handled below */

        for (k = 0; k < nfds; k++) {
            if (pfds[k].revents & (POLLOUT | POLLERR | POLLHUP)) {
                int idxh = idx[k];
                int sockerr = 0;
                socklen_t len = sizeof(sockerr);

                getsockopt(batch[idxh].fd, SOL_SOCKET, SO_ERROR, &sockerr, &len);
                batch[idxh].reachable = (sockerr == 0);
                close(batch[idxh].fd);
                batch[idxh].fd = -1;
                remaining--;
            }
        }
    }

    /* Anything still pending timed out. */
    for (i = 0; i < n; i++) {
        if (batch[i].reachable == -1) {
            if (batch[i].fd >= 0)
                close(batch[i].fd);
            batch[i].reachable = 0;
        }
    }

    Free((void **) &idx);
    Free((void **) &pfds);
}

static void filter_unreachable_hosts(opt_t *opt)
{
    hostlist_t           wcoll       = opt->wcoll;
    hostlist_t           unreachable = hostlist_create(NULL);
    hostlist_iterator_t  wi          = hostlist_iterator_create(wcoll);
    int                  concurrency = opt->fanout > 0 ?
                                        opt->fanout : REACHABLE_DEFAULT_CONCURRENCY;
    bool                 use_tcp     = opt->rcmd_name &&
                                        strcmp(opt->rcmd_name, "ssh") == 0;
    struct probe        *batch       = Malloc(concurrency * sizeof(*batch));
    char                *host;
    int                  n;
    int                  i;

    do {
        n = 0;
        while (n < concurrency && (host = hostlist_next(wi))) {
            batch[n].host = host; /* owned - freed below */
            n++;
        }

        if (n == 0)
            break;

        if (use_tcp)
            run_tcp_probe_batch(batch, n, tcp_port);
        else
            run_icmp_probe_batch(batch, n);

        for (i = 0; i < n; i++) {
            if (!batch[i].reachable)
                hostlist_push_host(unreachable, batch[i].host);
            free(batch[i].host);
        }
    } while (n == concurrency);

    hostlist_iterator_destroy(wi);
    Free((void **) &batch);

    if (hostlist_count(unreachable) > 0) {
        hostlist_iterator_t ui = hostlist_iterator_create(unreachable);
        while ((host = hostlist_next(ui))) {
            hostlist_delete_host(wcoll, host);
            free(host);
        }
        hostlist_iterator_destroy(ui);

        if (report_file)
            write_report_file(unreachable);
    }

    hostlist_destroy(unreachable);
}

static void write_report_file(hostlist_t unreachable)
{
    FILE *fp = fopen(report_file, "w");
    hostlist_iterator_t i;
    char *host;

    if (!fp) {
        err("%p: reachable: unable to open %s: %m\n", report_file);
        return;
    }

    i = hostlist_iterator_create(unreachable);
    while ((host = hostlist_next(i))) {
        fprintf(fp, "%s\n", host);
        free(host);
    }
    hostlist_iterator_destroy(i);

    fclose(fp);
}

/*
 * vi: tabstop=4 shiftwidth=4 expandtab
 */
