/*****************************************************************************\
 *  nodeclass.c - GPFS/Spectrum Scale node class targeting misc module
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
 *  Modeled on IBM Spectrum Scale's mmdsh(8) "-N nodeclass" targeting:
 *  build the working collective from the members of one or more GPFS
 *  node classes (as reported by mmlsnodeclass(8)), resolved through
 *  mmlscluster(8) to the canonical admin node name pdsh should target,
 *  since mmlsnodeclass's member list isn't guaranteed to already be in
 *  the form (admin vs. daemon interface name, or a bare node number)
 *  that pdsh needs to actually reach the node.
 *
 *  Both commands are shelled out to and parsed via their "-Y" (colon
 *  delimited, self-describing header) output rather than the default
 *  human-readable tables, since column widths in the latter aren't
 *  stable across versions.
 *
 *  SCAFFOLD STATUS: the exact "-Y" column names below (nodeClassName,
 *  members, nodeNumber, adminNodeName, daemonNodeName) are inferred
 *  from IBM's command reference prose, not a captured sample of real
 *  output - this has not been run against an actual GPFS/Spectrum
 *  Scale cluster. The column lookup is name-based and case/substring
 *  tolerant specifically to survive minor naming drift, but the field
 *  names themselves need to be confirmed (and this module exercised
 *  end to end) on real hardware before relying on it. Known gaps:
 *    - "-Y" is documented to encode field values that would otherwise
 *      contain a literal colon (via mmclidecode); this parser does not
 *      decode that escaping.
 *    - node ID/name resolution is a simple linear scan over the
 *      cluster's node list per member - fine for typical cluster
 *      sizes, but a hash lookup would scale better on very large
 *      clusters.
\*****************************************************************************/
#if HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "src/common/hostlist.h"
#include "src/common/list.h"
#include "src/common/split.h"
#include "src/common/err.h"
#include "src/common/xmalloc.h"
#include "src/pdsh/mod.h"

#ifndef MMLSNODECLASS_PATH
#  define MMLSNODECLASS_PATH "/usr/lpp/mmfs/bin/mmlsnodeclass"
#endif
#ifndef MMLSCLUSTER_PATH
#  define MMLSCLUSTER_PATH "/usr/lpp/mmfs/bin/mmlscluster"
#endif

#define MAX_Y_FIELDS 64

#if STATIC_MODULES
#  define pdsh_module_info nodeclass_module_info
#  define pdsh_module_priority nodeclass_module_priority
#endif

int pdsh_module_priority = 10;

/* One mmlscluster row: node number plus its admin/daemon interface names. */
struct node_entry {
    char *number;
    char *admin;
    char *daemon;
};

/* A "-Y" HEADER row's column names for one record type, e.g. "nodeClasses". */
struct header_rec {
    char  *rectype;
    char **names;
    int    ncols;
};

static int  nodeclass_opt_n(opt_t *, int, char *);
static int  mod_nodeclass_exit(void);
static hostlist_t mod_nodeclass_wcoll(opt_t *opt);

static List class_list = NULL; /* requested class names, from -n */

/*
 * Export pdsh module operations structure
 */
struct pdsh_module_operations nodeclass_module_ops = {
    (ModInitF)       NULL,
    (ModExitF)       mod_nodeclass_exit,
    (ModReadWcollF)  mod_nodeclass_wcoll,
    (ModPostOpF)     NULL
};

/*
 * This module provides no rcmd connect method of its own.
 */
struct pdsh_rcmd_operations nodeclass_rcmd_ops = {
    (RcmdInitF)  NULL,
    (RcmdSigF)   NULL,
    (RcmdF)      NULL,
};

/*
 * Export module options
 */
struct pdsh_module_option nodeclass_module_options[] =
 { { 'n', "class,...", "target nodes in GPFS/Spectrum Scale node class(es) (mmdsh -N)",
     DSH | PCP, (optFunc) nodeclass_opt_n
   },
   PDSH_OPT_TABLE_END
 };

/*
 * Nodeclass module info
 */
struct pdsh_module pdsh_module_info = {
  "misc",
  "nodeclass",
  "Chris Maestas",
  "target nodes in a GPFS/Spectrum Scale node class, via mmlsnodeclass/mmlscluster",
  DSH | PCP,

  &nodeclass_module_ops,
  &nodeclass_rcmd_ops,
  &nodeclass_module_options[0],
};

static int nodeclass_opt_n(opt_t *pdsh_opt, int opt, char *arg)
{
    class_list = list_split_append(class_list, ",", arg);
    return 0;
}

static int mod_nodeclass_exit(void)
{
    if (class_list)
        list_destroy(class_list);
    return 0;
}

/*
 *  Fork `argv[0]' with `argv' and hand back a FILE* reading its stdout;
 *    `*pid_out' is the child to reap with waitpid() once done reading.
 *    Returns NULL on failure to fork/pipe/exec.
 */
static FILE *run_capture(char *const argv[], pid_t *pid_out)
{
    int    pipefd[2];
    pid_t  pid;

    if (pipe(pipefd) < 0) {
        err("%p: nodeclass: pipe: %m\n");
        return NULL;
    }

    pid = fork();
    if (pid < 0) {
        err("%p: nodeclass: fork: %m\n");
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        if (devnull >= 0)
            dup2(devnull, STDERR_FILENO);
        close(pipefd[1]);
        execv(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    *pid_out = pid;
    return fdopen(pipefd[0], "r");
}

/*
 *  Split a "-Y" line in place on ':', preserving empty fields (unlike
 *    src/common/split.c's list_split(), which collapses them - fatal
 *    for fixed-position parsing of output that uses "::" for reserved/
 *    empty columns). Returns the number of fields found, capping at max.
 */
static int split_colon(char *line, char *fields[], int max)
{
    int   n = 0;
    char *p = line;
    size_t len = strlen(p);

    if (len > 0 && p[len - 1] == '\n')
        p[len - 1] = '\0';

    while (n < max) {
        fields[n++] = p;
        char *colon = strchr(p, ':');
        if (!colon)
            break;
        *colon = '\0';
        p = colon + 1;
    }
    return n;
}

static int field_index(char **names, int n, const char *substr)
{
    int i;
    for (i = 0; i < n; i++) {
        if (names[i] && strcasestr(names[i], substr))
            return i;
    }
    return -1;
}

/*
 *  Strdup()/Malloc() prefix a magic-cookie header that plain free(3)
 *    doesn't know to back up over - anything allocated with them must
 *    be released with Free(), never free(). (hostlist_t strings are a
 *    separate allocator domain - hostlist.c uses plain malloc/strdup
 *    internally, so free() is correct for those - but every string in
 *    this file that we allocated ourselves came from Strdup()/Malloc().)
 */
static void free_header_rec(void *x)
{
    struct header_rec *hr = x;
    int i;

    for (i = 0; i < hr->ncols; i++)
        Free((void **) &hr->names[i]);
    Free((void **) &hr->names);
    Free((void **) &hr->rectype);
    Free((void **) &hr);
}

static struct header_rec *find_header(List headers, const char *rectype)
{
    ListIterator i = list_iterator_create(headers);
    struct header_rec *hr;

    while ((hr = list_next(i))) {
        if (strcmp(hr->rectype, rectype) == 0)
            break;
    }
    list_iterator_destroy(i);
    return hr;
}

/*
 *  Read a "-Y" formatted command's output from `fp', calling
 *    `row_cb(hr, values, nvalues, arg)' for every non-header data row,
 *    where `hr' is that row's record type's header (so the callback
 *    can look up columns by name via field_index()).
 */
typedef void (*YRowF)(struct header_rec *hr, char **values, int nvalues, void *arg);

static void parse_y_output(FILE *fp, YRowF row_cb, void *arg)
{
    List  headers = list_create(free_header_rec);
    char  linebuf[4096];

    while (fgets(linebuf, sizeof(linebuf), fp)) {
        char *fields[MAX_Y_FIELDS];
        int   n = split_colon(linebuf, fields, MAX_Y_FIELDS);

        if (n < 3)
            continue; /* not a well-formed -Y line */

        if (strcmp(fields[2], "HEADER") == 0 && n > 3) {
            struct header_rec *hr = Malloc(sizeof(*hr));
            int i;

            hr->rectype = Strdup(fields[1]);
            hr->ncols   = n - 3;
            hr->names   = Malloc(hr->ncols * sizeof(char *));
            for (i = 0; i < hr->ncols; i++)
                hr->names[i] = Strdup(fields[3 + i]);

            list_append(headers, hr);
        } else {
            struct header_rec *hr = find_header(headers, fields[1]);

            if (hr)
                row_cb(hr, fields + 3, n - 3, arg);
        }
    }

    list_destroy(headers);
}

/*
 *  mmlscluster -Y row callback: collect node number / admin / daemon
 *    name triples into the List passed as `arg'.
 */
static void cluster_row_cb(struct header_rec *hr, char **values, int nvalues, void *arg)
{
    List id_map = arg;
    int  idx_number = field_index(hr->names, hr->ncols, "nodenumber");
    int  idx_admin  = field_index(hr->names, hr->ncols, "adminnodename");
    int  idx_daemon = field_index(hr->names, hr->ncols, "daemonnodename");
    struct node_entry *e;

    if (idx_number < 0 || idx_number >= nvalues)
        return; /* not the node-listing record type */

    e = Malloc(sizeof(*e));
    e->number = Strdup(values[idx_number]);
    e->admin  = (idx_admin  >= 0 && idx_admin  < nvalues && *values[idx_admin])
                ? Strdup(values[idx_admin]) : NULL;
    e->daemon = (idx_daemon >= 0 && idx_daemon < nvalues && *values[idx_daemon])
                ? Strdup(values[idx_daemon]) : NULL;

    list_append(id_map, e);
}

/* ListDelF for a List of Strdup()'d strings - see free_header_rec's note. */
static void free_xstr(void *x)
{
    char *s = x;
    Free((void **) &s);
}

static void free_node_entry(void *x)
{
    struct node_entry *e = x;
    Free((void **) &e->number);
    Free((void **) &e->admin);
    Free((void **) &e->daemon);
    Free((void **) &e);
}

/*
 *  Run mmlscluster -Y and return the resulting List of node_entry, or
 *    an empty (non-NULL) List if the command can't be run - name
 *    resolution just falls back to using mmlsnodeclass's member names
 *    as-is in that case, since it's a best-effort refinement, not a
 *    hard requirement (see resolve_member()).
 */
static List build_node_id_map(void)
{
    List   id_map = list_create(free_node_entry);
    char  *argv[] = { MMLSCLUSTER_PATH, "-Y", NULL };
    pid_t  pid;
    FILE  *fp = run_capture(argv, &pid);

    if (!fp) {
        err("%p: nodeclass: unable to run %s; node names from mmlsnodeclass "
            "will be used unresolved\n", MMLSCLUSTER_PATH);
        return id_map;
    }

    parse_y_output(fp, cluster_row_cb, id_map);

    fclose(fp);
    waitpid(pid, NULL, 0);

    return id_map;
}

/*
 *  Resolve a member token from mmlsnodeclass (a node number, admin
 *    name, or daemon name) to the canonical admin node name pdsh
 *    should target. Returns NULL if no match was found in id_map, in
 *    which case the caller should use the token verbatim.
 */
static const char *resolve_member(List id_map, const char *token)
{
    ListIterator        i = list_iterator_create(id_map);
    struct node_entry   *e;
    const char          *result = NULL;

    while ((e = list_next(i))) {
        if ((e->number && strcmp(e->number, token) == 0) ||
            (e->admin  && strcmp(e->admin,  token) == 0) ||
            (e->daemon && strcmp(e->daemon, token) == 0)) {
            result = e->admin ? e->admin : e->daemon;
            break;
        }
    }
    list_iterator_destroy(i);
    return result;
}

struct members_ctx {
    List members; /* accumulated raw member name strings */
};

/*
 *  mmlsnodeclass -Y row callback: split the "members" column on comma
 *    and append each token to the members list.
 */
static void nodeclass_row_cb(struct header_rec *hr, char **values, int nvalues, void *arg)
{
    struct members_ctx *ctx = arg;
    int   idx_members = field_index(hr->names, hr->ncols, "member");
    List  tokens;
    ListIterator i;
    char *tok;

    if (idx_members < 0 || idx_members >= nvalues || !*values[idx_members])
        return;

    tokens = list_split(",", values[idx_members]);
    i = list_iterator_create(tokens);
    while ((tok = list_next(i)))
        list_append(ctx->members, Strdup(tok));
    list_iterator_destroy(i);
    list_destroy(tokens);
}

/*
 *  Run "mmlsnodeclass -Y <classes>" for the comma-joined class_list and
 *    return the raw (unresolved) member name List.
 */
static List query_nodeclass_members(const char *classes_arg)
{
    struct members_ctx ctx;
    char  *argv[] = { MMLSNODECLASS_PATH, (char *) classes_arg, "-Y", NULL };
    pid_t  pid;
    FILE  *fp = run_capture(argv, &pid);

    ctx.members = list_create(free_xstr);

    if (!fp) {
        errx("%p: nodeclass: unable to run %s\n", MMLSNODECLASS_PATH);
        return ctx.members; /* unreached - errx() exits */
    }

    parse_y_output(fp, nodeclass_row_cb, &ctx);

    fclose(fp);
    waitpid(pid, NULL, 0);

    return ctx.members;
}

/*
 *  Called by mod_read_wcoll() to build (part of) the initial working
 *    collective. Returns NULL if -n was never given, so this module is
 *    a no-op unless explicitly asked for one or more node classes.
 */
static hostlist_t mod_nodeclass_wcoll(opt_t *opt)
{
    hostlist_t wcoll;
    List       id_map;
    List       members;
    char       classes_arg[LINEBUFSIZE];
    ListIterator i;
    char      *member;

    if (!class_list || list_is_empty(class_list))
        return NULL;

    if ((size_t) list_join(classes_arg, sizeof(classes_arg), ",", class_list)
        >= sizeof(classes_arg))
        errx("%p: nodeclass: class list too long\n");

    id_map  = build_node_id_map();
    members = query_nodeclass_members(classes_arg);

    if (list_is_empty(members)) {
        errx("%p: nodeclass: no members found for class(es) \"%s\" - "
             "check the class name(s) with `mmlsnodeclass'\n", classes_arg);
    }

    wcoll = hostlist_create(NULL);

    i = list_iterator_create(members);
    while ((member = list_next(i))) {
        const char *resolved = resolve_member(id_map, member);
        hostlist_push_host(wcoll, resolved ? resolved : member);
    }
    list_iterator_destroy(i);

    list_destroy(members);
    list_destroy(id_map);

    return wcoll;
}

/*
 * vi: tabstop=4 shiftwidth=4 expandtab
 */
