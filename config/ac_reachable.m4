##*****************************************************************************
## $Id$
##*****************************************************************************
#  SYNOPSIS:
#    AC_REACHABLE
#
#  DESCRIPTION:
#    Check if user wants to compile the "reachable" misc module, and
#    locate a `ping' binary for it to shell out to. This module implements
#    mmdsh-style preflight reachability checking (mmdsh -v / -R).
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_REACHABLE],
[
  AC_MSG_CHECKING([for whether to build reachable module])
  AC_ARG_WITH([reachable],
    AS_HELP_STRING([--with-reachable],[Build reachable (preflight ping check) module]),
    [ case "$withval" in
        no)  ac_with_reachable=no ;;
        yes) ac_with_reachable=yes ;;
        *)   AC_MSG_RESULT([doh!])
             AC_MSG_ERROR([bad value "$withval" for --with-reachable]) ;;
      esac
    ]
  )
  AC_MSG_RESULT([${ac_with_reachable=yes}])

  if test "$ac_with_reachable" = "yes"; then
     AC_PATH_PROG([PING_PATH], [ping], [none], [$PATH:/bin:/sbin:/usr/bin:/usr/sbin])
     if test "$PING_PATH" = "none"; then
        AC_MSG_WARN([ping not found - disabling reachable module])
        ac_with_reachable=no
     else
        ac_have_reachable=yes
        AC_ADD_STATIC_MODULE("reachable")
        AC_DEFINE_UNQUOTED([PING_PATH], ["$PING_PATH"], [Path to ping(1)])
     fi
  fi
])
