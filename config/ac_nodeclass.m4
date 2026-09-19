##*****************************************************************************
## $Id$
##*****************************************************************************
#  SYNOPSIS:
#    AC_NODECLASS
#
#  DESCRIPTION:
#    Check if user wants to compile the "nodeclass" misc module, and
#    locate the `mmlsnodeclass' and `mmlscluster' binaries it shells out
#    to. This module implements mmdsh-style "-N nodeclass" targeting
#    (GPFS/Spectrum Scale node classes), resolved to canonical admin
#    node names via mmlscluster.
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_NODECLASS],
[
  AC_MSG_CHECKING([for whether to build nodeclass module])
  AC_ARG_WITH([nodeclass],
    AS_HELP_STRING([--with-nodeclass],[Build nodeclass (GPFS/Spectrum Scale -n targeting) module]),
    [ case "$withval" in
        no)  ac_with_nodeclass=no ;;
        yes) ac_with_nodeclass=yes ;;
        *)   AC_MSG_RESULT([doh!])
             AC_MSG_ERROR([bad value "$withval" for --with-nodeclass]) ;;
      esac
    ]
  )
  AC_MSG_RESULT([${ac_with_nodeclass=yes}])

  if test "$ac_with_nodeclass" = "yes"; then
     # Spectrum Scale binaries live in /usr/lpp/mmfs/bin, which is not
     # always on PATH even on a cluster node.
     AC_PATH_PROG([MMLSNODECLASS_PATH], [mmlsnodeclass], [none],
                  [$PATH:/usr/lpp/mmfs/bin])
     AC_PATH_PROG([MMLSCLUSTER_PATH], [mmlscluster], [none],
                  [$PATH:/usr/lpp/mmfs/bin])

     if test "$MMLSNODECLASS_PATH" = "none" || test "$MMLSCLUSTER_PATH" = "none"; then
        AC_MSG_WARN([mmlsnodeclass and/or mmlscluster not found - disabling nodeclass module (not a GPFS/Spectrum Scale node?)])
        ac_with_nodeclass=no
     else
        ac_have_nodeclass=yes
        AC_ADD_STATIC_MODULE("nodeclass")
        AC_DEFINE_UNQUOTED([MMLSNODECLASS_PATH], ["$MMLSNODECLASS_PATH"],
                            [Path to mmlsnodeclass(8)])
        AC_DEFINE_UNQUOTED([MMLSCLUSTER_PATH], ["$MMLSCLUSTER_PATH"],
                            [Path to mmlscluster(8)])
     fi
  fi
])
