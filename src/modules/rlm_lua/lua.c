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
 * @file lua.c
 * @brief Library functions for the lua module.
 *
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include "config.h"
#include "lua.h"

#include <lauxlib.h>
#include <lualib.h>

#define RLM_LUA_STACK_SET()	int _rlm_lua_stack_state = lua_gettop(L)
#define RLM_LUA_STACK_RESET()	lua_settop(L, _rlm_lua_stack_state)

#ifndef HAVE_PTHREAD_H
#define pthread_mutex_lock(_x)
#define pthread_mutex_unlock(_x)
#endif



fr_thread_local_setup(REQUEST *, rlm_lua_request);	/* macro */
fr_thread_local_setup(lua_State *, rlm_lua_interp);	/* macro */

static int c_to_lua(lua_State *L, VALUE_PAIR const *vp)
{
	char	buf[1024];

	if (!vp) return -1;

	switch (vp->da->type) {
	case PW_TYPE_ABINARY:
	case PW_TYPE_DATE:
	case PW_TYPE_ETHERNET:
	case PW_TYPE_IPADDR:
	case PW_TYPE_IPV6ADDR:
	case PW_TYPE_IPV4PREFIX:
	case PW_TYPE_IPV6PREFIX:
	case PW_TYPE_IFID:
	case PW_TYPE_OCTETS:
	case PW_TYPE_TLV:
	case PW_TYPE_STRING:
	case PW_TYPE_INTEGER64:
		vp_prints_value(buf, sizeof(buf), vp, '\0');
		lua_pushstring(L, buf);
		break;

	case PW_TYPE_BYTE:
	case PW_TYPE_SHORT:
	case PW_TYPE_INTEGER:
	case PW_TYPE_SIGNED:
		lua_pushinteger(L, vp->vp_integer);
		break;

	default:
		ERROR("Cannot convert %s to Lua type", fr_int2str(dict_attr_types, vp->da->type, "<INVALID>"));
		return -1;
	}
	return 0;
}

static VALUE_PAIR *lua_to_c(REQUEST *request, lua_State *L, DICT_ATTR const *da)
{
	VALUE_PAIR *vp;
	vp = pairalloc(request, da);
	char *p;

	if (lua_isnumber(L, -1) == 1) {
		switch (vp->da->type) {
		case PW_TYPE_STRING:
			p = talloc_asprintf(vp, "%f", lua_tonumber(L, -1));
			pairstrsteal(vp, p);
			break;

		case PW_TYPE_INTEGER:
			vp->vp_integer = (uint32_t) lua_tointeger(L, -1);
			vp->length = 4;
			break;

		case PW_TYPE_IPADDR:
		case PW_TYPE_COMBO_IP:
			vp->vp_ipaddr = (uint32_t) lua_tointeger(L, -1);
			vp->length = 4;
			break;

		case PW_TYPE_DATE:
			vp->vp_date = (uint32_t) lua_tointeger(L, -1);
			vp->length = 4;
			break;

		case PW_TYPE_OCTETS:
		{
			lua_Number number = lua_tonumber(L, -1);
			pairmemcpy(vp, (uint8_t*) &number, sizeof(number));
		}
			break;

		case PW_TYPE_BYTE:
			vp->vp_byte = (uint8_t) lua_tointeger(L, -1);
			vp->length = 1;

			break;
		case PW_TYPE_SHORT:
			vp->vp_short = (uint16_t) lua_tointeger(L, -1);
			vp->length = 2;

			break;
		case PW_TYPE_SIGNED:
			vp->vp_signed = (int32_t) lua_tointeger(L, -1);
			vp->length = 4;
			break;

		case PW_TYPE_INTEGER64:
			vp->vp_integer64 = (uint64_t) lua_tointeger(L, -1);
			vp->length = 8;
			break;

		default:
			REDEBUG("Invalid attribute type");
			return NULL;
		}

	} else if (lua_isstring(L, -1)) {
		pairparsevalue(vp, lua_tostring(L, -1));
	} else if (lua_islightuserdata(L, -1) || lua_isuserdata(L, -1)) {
		size_t len = lua_objlen(L, -1);
		if(len == 0) {
			REDEBUG("Cant determine length of user data");
			return NULL;
		}
		vp -> vp_octets = talloc_memdup(vp, lua_tostring(L, -1), lua_objlen(L, -1));
	} else {
		REDEBUG("Unknown data type");
		return NULL;
	}

	return vp;
}

/** Check whether the Lua interpreter were actually linked to is LuaJIT
 *
 * @param L Lua interpreter.
 * @return true if were running with LuaJIT else false.
 */
bool rlm_lua_isjit(lua_State *L)
{
	bool ret = false;
	RLM_LUA_STACK_SET();
	lua_getglobal(L, "jit");
	if (lua_isnil(L, -1)) {
		goto done;
	}
	ret = true;
done:
	RLM_LUA_STACK_RESET();
	return ret;
}

char const *rlm_lua_version(lua_State *L)
{
	char const *version;

	RLM_LUA_STACK_SET();
	lua_getglobal(L, "jit");
	if (!lua_isnil(L, -1)) {
		lua_getfield(L, -1, "version");	/* Version field in jit table */
	} else {
		lua_getglobal(L, "_VERSION");	/* Version global */
	}
	version = lua_tostring(L, -1);
	RLM_LUA_STACK_RESET();
	if (!version) {
		return NULL;
	}

	return version;
}

/** Lua function to output debug messages
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int l_log_debug(lua_State *L)
{
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		DEBUG("%s", msg);
	}

	return 0;
}

/** Lua function to output informational messages
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int l_log_info(lua_State *L)
{
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		INFO("%s", msg);
	}

	return 0;
}


/** Lua function to output warning messages
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int l_log_warn(lua_State *L)
{
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		WARN("%s", msg);
	}

	return 0;
}

/** Lua function to output error messages.
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int l_log_error(lua_State *L)
{
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *message = lua_tostring(L, idx);
		ERROR("%i: %s", idx, message);
		lua_pop(L, 1);
	}

	return 0;
}

/** Insert cdefs into the lua environment
 *
 * For LuaJIT using the FFI is significantly faster than the Lua interface.
 * Help people wishing to use the FFI by inserting cdefs for standard functions.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments).
 */
static int rlm_lua_cdefs(rlm_lua_t *inst, lua_State *L)
{
	if (luaL_dostring(L,"\
		ffi = require(\"ffi\")\
		ffi.cdef [[\
			typedef enum log_type {\
				L_AUTH = 2,\
				l_log_info = 3,\
				L_ERR = 4,\
				L_WARN = 5,\
				L_PROXY	= 6,\
				L_ACCT = 7,\
				L_DBG = 16,\
				L_DBG_WARN = 17,\
				L_DBG_ERR = 18,\
				L_DBG_WARN2 = 19,\
				L_DBG_ERR2 = 20\
			} log_type_t;\
			int radlog(log_type_t lvl, char const *fmt, ...);\
			]]\
		fr_srv = ffi.load(\"freeradius-server\")\
		fr = ffi.load(\"freeradius-lua\")\
		fr.debug = function(msg)\
		   fr_srv.radlog(16, \"%s\", msg)\
		end\
		fr.info = function(msg)\
		   fr_srv.radlog(3, \"%s\", msg)\
		end\
		fr.warn = function(msg)\
		   fr_srv.radlog(5, \"%s\", msg)\
		end\
		fr.error = function(msg)\
		   fr_srv.radlog(4, \"%s\", msg)\
		end\
		") != 0) {
		ERROR("rlm_lua (%s): Failed setting up FFI: %s", inst->xlat_name,
		      lua_gettop(L) ? lua_tostring(L, -1) : "Unknown error");
		return -1;
	}

	return 0;
}

/** Check whether we can call a Lua function successfully.
 *
 * @param L Lua interpreter.
 * @param name of the function.
 * @return 0 on success -1 on failure.
 */
static int rlm_lua_check_arg(rlm_lua_t *inst, lua_State *L, char const *name)
{
	static double a = 5, b = 5;
	int ret;
	RLM_LUA_STACK_SET();

	lua_getglobal(L, name);
	lua_pushnumber(L, a);
	lua_pushnumber(L, b);

	if (lua_pcall(L, 2, 1, 0) != 0) {
		char const *msg = lua_tostring(L, -1);
		ERROR("rlm_lua (%s): Call to %s failed: %s", inst->xlat_name, name, msg ? msg : "unknown error");
		ret = -1;

		goto done;
	}
	ret = 0;
done:
	RLM_LUA_STACK_RESET();
	return ret;
}

/** Check if a given function was loaded into an index in the global table
 *
 * Also check what was loaded there is a function and that it accepts the correct arguments.
 *
 * @param inst Current instance of rlm_lua
 * @param name of function to check.
 * @returns 0 on success (function is present and correct), or -1 on failure.
 */
static int rlm_lua_check_func(rlm_lua_t *inst, lua_State *L, char const *name)
{
	int ret;
	RLM_LUA_STACK_SET();

	if (name == NULL) return 0;

	lua_getglobal(L, name);

	/*
	 *	Check the global is a function.
	 */
	if (!lua_isfunction(L, -1)) {
		int type = lua_type(L, -1);

		if (type == LUA_TNIL) {
			ERROR("rlm_lua (%s): Function \"%s\" not found ", inst->xlat_name, name);
		} else {
			ERROR("rlm_lua (%s): Value found at index \"%s\" is not a function (is a %s)",
			      inst->xlat_name, name, lua_typename(L, type));
		}

		ret = -1;
		goto done;
	}

/*
	if (rlm_lua_check_arg(inst, L, name) < 0) {
		ret = -1;
		goto done;
	}
*/
	ret = 0;
done:
	RLM_LUA_STACK_RESET();
	return ret;
}

static int lua_get_attribute(lua_State *L)
{
	vp_cursor_t cursor;
	DICT_ATTR const *da;
	VALUE_PAIR *vp = NULL;
	int index;
	REQUEST *request = fr_thread_local_get(rlm_lua_request);

	if (!lua_islightuserdata(L, lua_upvalueindex(1))) {
		REDEBUG("DICT_ATTR not available in upvalues, can't determine target attribute");
		return -1;
	}

	da = lua_touserdata(L, lua_upvalueindex(1));
	if (!da) {
		REDEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}

	/* Packet list should be light user data too at some point... */
	fr_cursor_init(&cursor, &request->packet->vps);

	for (index = (int) lua_tointeger(L, -1); index >= 0; index--) {
		vp = fr_cursor_next_by_da(&cursor, da, TAG_ANY);
		if (!vp) {
			return 0;
		}
	}

	if (c_to_lua(L, vp) < 0) {
		return -1;
	}

	return 1;
}

static int lua_set_attribute(lua_State *L)
{
	vp_cursor_t cursor;
	DICT_ATTR const *da;
	VALUE_PAIR *vp = NULL, *new;
	int index;
	REQUEST *request = fr_thread_local_get(rlm_lua_request);

	if (!lua_islightuserdata(L, lua_upvalueindex(1))) {
		REDEBUG("DICT_ATTR not available in upvalues, can't determine target attribute");
		return -1;
	}

	da = lua_touserdata(L, lua_upvalueindex(1));
	if (!da) {
		REDEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}

	if ((new = lua_to_c(request, L, da)) == NULL) {
		return 0;
	}

	/* Packet list should be light user data too at some point... */
	fr_cursor_init(&cursor, &request->packet->vps);

	for (index = (int) lua_tointeger(L, -2); index >= 0; index--) {
		vp = fr_cursor_next_by_da(&cursor, da, TAG_ANY);
		if (!vp) {
			fr_cursor_insert(&cursor, new);
			return 0;
		}
	}

	fr_cursor_replace(&cursor, new);

	return 0;
}

static int lua_list_attr(lua_State *L)
{
	vp_cursor_t *cursor;
	VALUE_PAIR *vp;

	if (!(lua_isuserdata(L, lua_upvalueindex(1)))) {
		return -1;
	}

	cursor = lua_touserdata(L, lua_upvalueindex(1));
	if (!cursor) {
		DEBUG("Failed retrieving vp_cursor_t from upvalues");
		return -1;
	}

	/* Packet list should be light user data too at some point... */
	if((vp = fr_cursor_current(cursor)) == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushstring(L, vp->da->name);

	if (c_to_lua(L, vp) < 0) {
		return -1;
	}

	fr_cursor_next(cursor);

	return 2;
}

static int list_constructor(lua_State *L)
{
	vp_cursor_t *cursor;

	cursor = lua_touserdata(L, lua_upvalueindex(1));
	if (!cursor) {
		DEBUG("Failed retrieving vp_cursor_t from upvalues");
		return -1;
	}
	lua_pushlightuserdata(L, cursor);
	lua_pushcclosure(L, lua_list_attr, 1);

	return 1;
}

static int lua_next_attr(lua_State *L)
{
	vp_cursor_t *cursor;
	DICT_ATTR const *da;
	VALUE_PAIR *vp;

	if (!(lua_isuserdata(L, lua_upvalueindex(1)))) {
		return -1;
	}

	cursor = lua_touserdata(L, lua_upvalueindex(1));
	if (!cursor) {
		DEBUG("Failed retrieving vp_cursor_t from upvalues");
		return -1;
	}

	if (!(lua_isuserdata(L, lua_upvalueindex(2)))) {
		return -1;
	}

	da = lua_touserdata(L, lua_upvalueindex(2));
	if (!da) {
		DEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}

	/* Packet list should be light user data too at some point... */
	if((vp = fr_cursor_next_by_da(cursor, da, TAG_ANY)) == NULL) {
		lua_pushnil(L);
		return 1;
	}

	if (c_to_lua(L, vp) < 0) {
		return -1;
	}

	return 1;
}

static int next_constructor(lua_State *L)
{
	vp_cursor_t *cursor;
	DICT_ATTR const *da;
	DICT_ATTR *up;
	VALUE_PAIR *vp;

	da = lua_touserdata(L, lua_upvalueindex(2));
	if (!da) {
		DEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}
	memcpy(&up, &da, sizeof(up));

	vp = lua_touserdata(L, lua_upvalueindex(1));
	if (!vp) {
		DEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}
	cursor = (vp_cursor_t*) lua_newuserdata(L, sizeof(vp_cursor_t));
	fr_cursor_init(cursor, &vp);
	lua_pushlightuserdata(L, up);
	lua_pushcclosure(L, lua_next_attr, 2);

	return 1;
}

static int lua_new_attribute_table(lua_State *L)
{
	char const *attr;
	DICT_ATTR const *da;
	DICT_ATTR *up;
	REQUEST *request = fr_thread_local_get(rlm_lua_request);

	attr = lua_tostring(L, -1);
	if (!attr) {
		REDEBUG("Invalid attribute \"%s\"", attr);
		return -1;
	}

	da = dict_attrbyname(attr);
	if (!da) {
		REDEBUG("Invalid attribute \"%s\"", attr);
		return -1;
	}
	memcpy(&up, &da, sizeof(up));

	lua_newtable(L);	/* Attribute value table */
	lua_pushlightuserdata(L, request->packet->vps);
	lua_pushlightuserdata(L, up);
	lua_pushcclosure(L, next_constructor, 2);
	lua_setfield(L, -2, "pairs");
	lua_newtable(L);	/* Attribute value meta-table */
	lua_pushlightuserdata(L, up);
	lua_pushcclosure(L, lua_get_attribute, 1);
	lua_setfield(L, -2, "__index");
	lua_pushlightuserdata(L, up);
	lua_pushcclosure(L, lua_set_attribute, 1);
	lua_setfield(L, -2, "__newindex");

	lua_setmetatable(L, -2);
	lua_settable(L, -3);
	lua_getfield(L, -1, attr);

	return 1;
}

/** Initialise a new LuaJIT interpreter
 *
 * Creates a new lua_State and verifies all required functions have been loaded correctly.
 *
 * @param out Where to write a pointer to the new state.
 * @param instance Current instance of rlm_lua.
 * @return 0 on success else -1.
 */
int lua_init(lua_State **out, rlm_lua_t *instance)
{
	rlm_lua_t *inst = instance;
	lua_State *L = luaL_newstate();
	if (!L) {
		ERROR("rlm_lua (%s): Failed initialising Lua state", inst->xlat_name);
		return -1;
	}

	luaL_openlibs(L);

	/*
	 *	Load the Lua file into our environment.
	 *
	 *	When we spawn new connections we copy the compiled functions
	 *	between this L the the slave Ls.
	 */
	if (luaL_loadfile(L, inst->module) != 0) {
		ERROR("rlm_lua (%s): Failed loading file: %s", inst->xlat_name,
		      lua_gettop(L) ? lua_tostring(L, -1) : "Unknown error");

		goto error;
	}

	if (lua_pcall(L, 0, LUA_MULTRET, 0) != 0) {
		ERROR("rlm_lua (%s): Failed executing script: %s", inst->xlat_name,
		      lua_gettop(L) ? lua_tostring(L, -1) : "Unknown error");

		goto error;
	}

	if (inst->jit) {
		DEBUG4("rlm_lua (%s): Initialised new LuaJIT interpreter %p", inst->xlat_name, L);
		rlm_lua_cdefs(inst, L);
	} else {
		DEBUG4("rlm_lua (%s): Initialised new Lua interpreter %p", inst->xlat_name, L);
		lua_newtable(L);
		lua_pushcfunction(L, l_log_debug);
		lua_setfield(L, -2, "debug");

		lua_pushcfunction(L, l_log_info);
		lua_setfield(L, -2, "info");

		lua_pushcfunction(L, l_log_warn);
		lua_setfield(L, -2, "warn");

		lua_pushcfunction(L, l_log_error);
		lua_setfield(L, -2, "error");
		lua_setglobal(L, "fr");
	}

	/*
	 *	Verify all the functions were provided.
	 */
	if (rlm_lua_check_func(inst, L, inst->func_authorize)
	    || rlm_lua_check_func(inst, L, inst->func_authenticate)
#ifdef WITH_ACCOUNTING
	    || rlm_lua_check_func(inst, L, inst->func_preacct)
	    || rlm_lua_check_func(inst, L, inst->func_accounting)
#endif
	    || rlm_lua_check_func(inst, L, inst->func_checksimul)
#ifdef WITH_PROXY
	    || rlm_lua_check_func(inst, L, inst->func_pre_proxy)
	    || rlm_lua_check_func(inst, L, inst->func_post_proxy)
#endif
	    || rlm_lua_check_func(inst, L, inst->func_post_auth)
#ifdef WITH_COA
	    || rlm_lua_check_func(inst, L, inst->func_recv_coa)
	    || rlm_lua_check_func(inst, L, inst->func_send_coa)
#endif
	    || rlm_lua_check_func(inst, L, inst->func_detach)
	    || rlm_lua_check_func(inst, L, inst->func_xlat)) {
	 	goto error;
	}

	*out = L;
	return 0;

	error:
	*out = NULL;

	lua_close(L);
	return -1;
}

int do_lua(rlm_lua_t *inst, REQUEST *request, char const *funcname)
{
	vp_cursor_t cursor;
	lua_State *L;

	fr_thread_local_set(rlm_lua_request, request);

#ifdef HAVE_PTHREAD_H
	if (!inst->threads) {
		L = inst->interpreter;
		pthread_mutex_lock(&inst->mutex);
	} else {
		L = pthread_getspecific(inst->key);
		if (!L) {
			if (lua_init(&L, inst) < 0) {
				return -1;
			}
			pthread_setspecific(inst->key, L);
		}
	}
#else
	L = inst->interpreter;
#endif

	RDEBUG2("Calling %s() in interpreter %p", funcname, L);

	RLM_LUA_STACK_SET();
	pairsort(&request->packet->vps, true);
	fr_cursor_init(&cursor, &request->packet->vps);

	/*
	 *	Setup the environment
	 */
	lua_newtable(L);	/* Attribute list table */
	lua_pushlightuserdata(L, &cursor);
	lua_pushcclosure(L, list_constructor, 1);
	lua_setfield(L, -2, "pairs_list");
	lua_newtable(L);	/* Attribute list meta-table */
	lua_pushinteger(L, PAIR_LIST_REQUEST);
	lua_pushcclosure(L, lua_new_attribute_table, 1);
	lua_setfield(L, -2, "__index");

//	lua_pushcfunction(L, new_index);
//	lua_setfield(L, -2, "__newindex");

	lua_setmetatable(L, -2);
	lua_setglobal(L, "request");

	/*
	 *	Get the function were going to be calling
	 */
	lua_getglobal(L, funcname);
	if (lua_pcall(L, 0, 0, 0)) {

	} else {

	}
	RLM_LUA_STACK_RESET();
	if (!inst->threads) {
		pthread_mutex_unlock(&inst->mutex);
	}

	return 0;
}
