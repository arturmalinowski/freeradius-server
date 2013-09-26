AC_PREREQ([2.53])
AC_INIT(rlm_lua.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_lua])
m4_include([m4/ax_lua.m4])

if test x$with_[]modname != xno; then
	AC_PROG_CC
	AC_PROG_CPP

	LUA_VERSION=jit-2.0
	AX_LUA_HEADERS

	dnl #
	dnl # Fall back to standard Lua if we can't find LuaJIT
	dnl #
	if test "x$ac_cv_header_lua_h" = "xno"; then
		AC_MSG_NOTICE([Using Lua])
		dnl #
		dnl # This is the minimum version of Lua we can work with
		dnl #
		LUA_VERSION=5.1
		AX_LUA_HEADERS
		if test "x$ac_cv_header_lua_h" = "xyes"; then
			AC_MSG_NOTICE([Falling back to Lua 5.1, for optimal performance rebuild with LuaJIT 2])
		fi
	else
		AC_MSG_NOTICE([Using LuaJIT])
		dnl #
		dnl # Version of LuaJIT compatibile with the 5.1 API
		dnl #
		LUA_VERSION=jit-5.1
	fi

	if test "x$ac_cv_header_lua_h" = "xyes"; then
		AX_LUA_LIBS

		if test "x$_ax_found_lua_libs" != 'xyes'; then
			fail="Lua libs"
		fi
	else
		fail="Lua headers"
	fi

	lua_cflags="$LUA_INCLUDE"
	lua_ldflags="$LUA_LIB"

	targetname=modname     # keep this!  Don't change!
else
	targetname=            # keep this!  Don't change!
	echo \*\*\* module modname is disabled.  # keep this!  Don't change!
fi

dnl  Don't change this section.
if test x"$fail" != x""; then
	if test x"${enable_strict_dependencies}" = x"yes"; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi

AC_SUBST(lua_cflags)
AC_SUBST(lua_ldflags)

AC_CONFIG_HEADER(config.h)

AC_SUBST(targetname)  # keep this!  Don't change!
AC_OUTPUT(rlm_lua.mk)  # keep this!  Don't change!
AC_OUTPUT(libfreeradius-lua.mk)  # keep this!  Don't change!
