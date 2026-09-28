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
 *  Modeled on IBM Spectrum Scale's mmdsh(8) "-N" targeting: build the
 *  working collective from GPFS node classes and/or node numbers.
 *  Class membership comes from the allMembers column of
 *  "mmlsnodeclass <classes> -Y" (which includes members of nested
 *  classes), and every target is resolved to its admin node name
 *  through the clusterNode records of "mmlscluster -Y".
 *
 *  Both commands are parsed from their -Y output (colon-delimited, with
 *  a HEADER row naming each column), looking columns up by name rather
 *  than position. -Y encodes values that contain a colon (mmclidecode);
 *  that encoding isn't decoded here, since the node and class names
 *  and node numbers read don't normally contain one.
\*****************************************************************************/
#if HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
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
 { { 'n', "node/class,...",
     "target GPFS node classes or node numbers/ranges (mmdsh -N)",
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
  "target GPFS/Spectrum Scale node classes or node numbers",
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
 *    stderr is left alone so the command's own error messages reach the
 *    user. `*pid_out' is the child to reap with finish_capture().
 *    Returns NULL if the pipe or fork fails.
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
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execv(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    *pid_out = pid;
    return fdopen(pipefd[0], "r");
}

/*
 *  Close the stream from run_capture() and reap its child.
 *    Returns 0 if the command exited successfully, -1 otherwise.
 */
static int finish_capture(FILE *fp, pid_t pid)
{
    int status;

    fclose(fp);
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
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
    char *colon;
    size_t len = strlen(p);

    if (len > 0 && p[len - 1] == '\n')
        p[len - 1] = '\0';

    while (n < max) {
        fields[n++] = p;
        colon = strchr(p, ':');
        if (!colon)
            break;
        *colon = '\0';
        p = colon + 1;
    }
    return n;
}

/*
 *  Case-insensitive substring test. strcasestr(3) would do, but it is a
 *    GNU extension that glibc only declares under _GNU_SOURCE.
 */
static int contains_nocase(const char *str, const char *substr)
{
    size_t len = strlen(substr);

    for (; *str; str++) {
        if (strncasecmp(str, substr, len) == 0)
            return 1;
    }
    return 0;
}

static int field_index(char **names, int n, const char *substr)
{
    int i;
    for (i = 0; i < n; i++) {
        if (names[i] && contains_nocase(names[i], substr))
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
    struct header_rec *matched = NULL;

    while ((hr = list_next(i))) {
        if (hr->rectype && rectype && strcmp(hr->rectype, rectype) == 0) {
            matched = hr;
            break;
        }
    }
    list_iterator_destroy(i);
    if (!matched && list_count(headers) == 1)
        matched = list_peek(headers);
    return matched;
}

/*
 *  Read a "-Y" formatted command's output from `fp', calling
 *    `row_cb(hr, values, nvalues, arg)' for every non-header data row,
 *    where `hr' is that row's record type's header (so the callback
 *    can look up columns by name via field_index()).
 */
typedef void (*YRowF)(struct header_rec *hr, char **values, int nvalues,
                      void *arg);

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
 *    name triples into the List passed as `arg'. Only records with an
 *    admin name column count; mmlscluster also emits other per-node
 *    records (e.g. commentNode) that carry a node number but no admin
 *    name.
 */
static void cluster_row_cb(struct header_rec *hr, char **values,
                           int nvalues, void *arg)
{
    List id_map = arg;
    int  idx_number = field_index(hr->names, hr->ncols, "nodenumber");
    int  idx_admin  = field_index(hr->names, hr->ncols, "adminnodename");
    int  idx_daemon = field_index(hr->names, hr->ncols, "daemonnodename");
    struct node_entry *e;

    if (idx_number < 0 || idx_number >= nvalues
        || idx_admin < 0 || idx_admin >= nvalues)
        return;

    e = Malloc(sizeof(*e));
    e->number = Strdup(values[idx_number]);
    e->admin  = *values[idx_admin] ? Strdup(values[idx_admin]) : NULL;
    e->daemon = (idx_daemon >= 0 && idx_daemon < nvalues
                 && *values[idx_daemon]) ? Strdup(values[idx_daemon]) : NULL;

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
 *  Run mmlscluster -Y and return the resulting List of node_entry. If
 *    the command fails, warn and return what was read (possibly an
 *    empty List): class members are then used unresolved, and node
 *    numbers can't be resolved at all (see resolve_member()).
 */
static List build_node_id_map(void)
{
    List   id_map = list_create(free_node_entry);
    char  *argv[] = { MMLSCLUSTER_PATH, "-Y", NULL };
    pid_t  pid;
    FILE  *fp = run_capture(argv, &pid);

    if (fp) {
        parse_y_output(fp, cluster_row_cb, id_map);
        if (finish_capture(fp, pid) == 0)
            return id_map;
    }

    err("%p: nodeclass: %s failed; node names will not be resolved\n",
        MMLSCLUSTER_PATH);
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

/*
 *  Check if a string looks like a node number or range ("3", "1-4",
 *    "1..4") rather than a node class name.
 */
static int is_node_id_or_range(const char *str)
{
    const char *p = str;
    int has_digit = 0;

    if (!str || !*str)
        return 0;

    while (*p) {
        if (isdigit((unsigned char)*p))
            has_digit = 1;
        else if (*p != '-' && *p != ',' && *p != '.')
            return 0;
        p++;
    }
    return has_digit;
}

/*
 *  Parse a node number or range ("3", "1-4") into [*lo, *hi].
 *    Returns 0 on success, -1 if `str' isn't one of those forms.
 */
static int parse_node_range(const char *str, long *lo, long *hi)
{
    char *end;

    *lo = *hi = 0;
    if (!isdigit((unsigned char) *str))
        return -1;
    *lo = *hi = strtol(str, &end, 10);
    if (*end == '-') {
        str = end + 1;
        if (!isdigit((unsigned char) *str))
            return -1;
        *hi = strtol(str, &end, 10);
    }
    if (*end != '\0')
        return -1;
    if (*lo > *hi) {
        long tmp = *lo;
        *lo = *hi;
        *hi = tmp;
    }
    return 0;
}

/*
 *  Append the admin name of every cluster node whose number falls in
 *    the node spec (e.g. "1-4", "1..4", "11,12") to members. Walks the
 *    cluster's node list rather than the range itself, so a huge range
 *    costs no more than the cluster size, and gaps in the numbering are
 *    skipped. Exits with an error if the spec is malformed, or if any
 *    part of it matches no node.
 */
static void expand_node_id_range(List id_map, const char *spec, List members)
{
    char *copy = Strdup(spec);
    char *p = copy;
    char *next;
    char *end;
    long lo, hi, num;
    int matched;
    ListIterator i;
    struct node_entry *e;

    /* Accept "1..4" as a synonym for "1-4" */
    while ((p = strstr(copy, ".."))) {
        *p = '-';
        memmove(p + 1, p + 2, strlen(p + 2) + 1);
    }

    for (p = copy; p; p = next) {
        if ((next = strchr(p, ',')))
            *next++ = '\0';

        if (parse_node_range(p, &lo, &hi) < 0)
            errx("%p: nodeclass: invalid node number or range \"%s\"\n",
                 spec);

        matched = 0;
        i = list_iterator_create(id_map);
        while ((e = list_next(i))) {
            num = strtol(e->number, &end, 10);
            if (*end == '\0' && num >= lo && num <= hi && e->admin) {
                list_append(members, Strdup(e->admin));
                matched++;
            }
        }
        list_iterator_destroy(i);

        if (!matched)
            errx("%p: nodeclass: no cluster node matches \"%s\"\n", spec);
    }

    Free((void **) &copy);
}

struct members_ctx {
    List members; /* accumulated raw member name strings */
};

/*
 *  mmlsnodeclass -Y row callback: split the allMembers column (falling
 *    back to memberNodes) on comma and append each node name to the
 *    members list. The search must not settle for a bare "member"
 *    match first: memberClasses, which comes earlier, lists nested
 *    class names, not nodes.
 */
static void nodeclass_row_cb(struct header_rec *hr, char **values,
                             int nvalues, void *arg)
{
    struct members_ctx *ctx = arg;
    int   idx_members;
    List  tokens;
    ListIterator i;
    char *tok;

    idx_members = field_index(hr->names, hr->ncols, "allmembers");
    if (idx_members < 0)
        idx_members = field_index(hr->names, hr->ncols, "membernodes");
    if (idx_members < 0)
        idx_members = field_index(hr->names, hr->ncols, "member");

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
 *  Run "mmlsnodeclass <classes> -Y" and return the raw (unresolved)
 *    member name List. Exits with an error if the command fails, which
 *    it does if any one of the named classes doesn't exist - even
 *    though it still prints the members of the classes that do.
 */
static List query_nodeclass_members(const char *classes_arg)
{
    struct members_ctx ctx;
    char  *argv[] = { MMLSNODECLASS_PATH, (char *) classes_arg, "-Y", NULL };
    pid_t  pid;
    FILE  *fp = run_capture(argv, &pid);

    ctx.members = list_create(free_xstr);

    if (fp)
        parse_y_output(fp, nodeclass_row_cb, &ctx);
    if (!fp || finish_capture(fp, pid) < 0)
        errx("%p: nodeclass: %s failed for \"%s\"\n",
             MMLSNODECLASS_PATH, classes_arg);

    return ctx.members;
}

/*
 *  Called by mod_read_wcoll() to build (part of) the initial working
 *    collective. Returns NULL if -n was never given, so this module is
 *    a no-op unless explicitly asked for node classes or numbers.
 */
static hostlist_t mod_nodeclass_wcoll(opt_t *opt)
{
    hostlist_t wcoll;
    List       id_map;
    List       members;
    List       class_queries;
    char       classes_arg[LINEBUFSIZE];
    ListIterator i;
    char      *token;
    char      *member;

    if (!class_list || list_is_empty(class_list))
        return NULL;

    id_map        = build_node_id_map();
    members       = list_create(free_xstr);
    class_queries = list_create(free_xstr);

    i = list_iterator_create(class_list);
    while ((token = list_next(i))) {
        if (is_node_id_or_range(token)) {
            expand_node_id_range(id_map, token, members);
        } else {
            list_append(class_queries, Strdup(token));
        }
    }
    list_iterator_destroy(i);

    if (!list_is_empty(class_queries)) {
        List qmembers;
        if ((size_t) list_join(classes_arg, sizeof(classes_arg), ",",
                               class_queries) >= sizeof(classes_arg))
            errx("%p: nodeclass: class list too long\n");

        qmembers = query_nodeclass_members(classes_arg);
        i = list_iterator_create(qmembers);
        while ((member = list_next(i))) {
            const char *resolved = resolve_member(id_map, member);
            list_append(members, Strdup(resolved ? resolved : member));
        }
        list_iterator_destroy(i);
        list_destroy(qmembers);
    }
    list_destroy(class_queries);

    if (list_is_empty(members)) {
        list_join(classes_arg, sizeof(classes_arg), ",", class_list);
        errx("%p: nodeclass: no nodes found for \"%s\"\n", classes_arg);
    }

    wcoll = hostlist_create(NULL);

    i = list_iterator_create(members);
    while ((member = list_next(i)))
        hostlist_push_host(wcoll, member);
    list_iterator_destroy(i);
    hostlist_uniq(wcoll);

    list_destroy(members);
    list_destroy(id_map);

    return wcoll;
}

/*
 * vi: tabstop=4 shiftwidth=4 expandtab
 */
