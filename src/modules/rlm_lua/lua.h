/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file lua.h
 * @brief Library function signatures for lua module.
 *
 */
#ifndef _RLM_LUA_H
#define _RLM_LUA_H

RCSIDH(lua_h, "$Id$");

/*
 *	If were using luajit, luajit.h will define a few more constants and
 *	then include lua.h. Lua 5.1 and LuaJIT 2.0 are API compatible.
 */
#ifdef HAVE_LUAJIT_H
#include <luajit.h>
#else
#include <lua.h>
#endif
#include <freeradius-devel/radiusd.h>
/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_lua {
	lua_State	*interpreter;
	const char	*xlat_name;
	const char 	*module;

	const char	*func_instantiate;
	const char	*func_detach;

	const char	*func_authorize;
	const char	*func_authenticate;
#ifdef WITH_ACCOUNTING
	const char	*func_preacct;
	const char	*func_accounting;
#endif
	const char	*func_checksimul;
#ifdef WITH_PROXY
	const char	*func_pre_proxy;
	const char	*func_post_proxy;
#endif
	const char	*func_post_auth;
#ifdef WITH_COA
	const char	*func_recv_coa;
	const char	*func_send_coa;
#endif
	const char	*func_xlat;
} rlm_lua_t;

int lua_init(lua_State **out, rlm_lua_t *instance);
int do_lua(rlm_lua_t *inst, REQUEST *request, char const *funcname);

#endif /*_RLM_LUA_H*/
