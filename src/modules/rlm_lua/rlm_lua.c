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
 * @file rlm_lua.c
 * @brief Translates requests between the server an a Lua interpreter.
 *
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "lua.h"

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "filename",  PW_TYPE_FILE_INPUT | PW_TYPE_REQUIRED,
	  offsetof(rlm_lua_t,module), NULL,  NULL},

	{ "func_instantiate", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_instantiate), NULL, NULL},
	{ "func_detach", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_detach), NULL, NULL},

	{ "func_authorize", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_authorize), NULL, NULL},
	{ "func_authenticate", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_authenticate), NULL, NULL},
#ifdef WITH_ACCOUNTING
	{ "func_accounting", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_accounting), NULL, NULL},
	{ "func_preacct", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_preacct), NULL, NULL},
#endif
	{ "func_checksimul", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_checksimul), NULL, NULL},
	{ "func_xlat", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_xlat), NULL, NULL},
#ifdef WITH_PROXY
	{ "func_pre_proxy", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_pre_proxy), NULL, NULL},
	{ "func_post_proxy", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_post_proxy), NULL, NULL},
#endif
	{ "func_post_auth", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_post_auth), NULL, NULL},
#ifdef WITH_COA
	{ "func_recv_coa", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_recv_coa), NULL, NULL},
	{ "func_send_coa", PW_TYPE_STRING_PTR,
	  offsetof(rlm_lua_t,func_send_coa), NULL, NULL},
#endif

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_lua_t *inst = instance;
	lua_State *L;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	if (lua_init(&L, inst) < 0) {
		return -1;
	}

	inst->jit = rlm_lua_isjit(L);
	if (!inst->jit) {
		WDEBUG("Using standard Lua interpreter, performance will be suboptimal");
	}

	DEBUG("rlm_lua (%s): Using %s interpreter", inst->xlat_name, rlm_lua_version(L));

	/*
	 *	Free the interpreter we just created
	 */
	inst->interpreter = L;

	return 0;
}

static int mod_detach(UNUSED void *instance)
{
	return 0;
}

#define DO_LUA(_s)\
static rlm_rcode_t mod_##_s(void *instance, REQUEST *request) {\
		rlm_lua_t *inst = instance;\
		if (!inst->func_##_s) {\
			return RLM_MODULE_NOOP;\
		}\
		if (do_lua(inst, request, inst->func_##_s) < 0) {\
			return RLM_MODULE_FAIL;\
		}\
		return RLM_MODULE_OK;\
}

DO_LUA(authorize)
DO_LUA(authenticate)
DO_LUA(preacct)
DO_LUA(accounting)

/*
 *	See if a user is already logged in. Sets request->simul_count to the
 *	current session count for this user and sets request->simul_mpp to 2
 *	if it looks like a multilink attempt based on the requested IP
 *	address, otherwise leaves request->simul_mpp alone.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static rlm_rcode_t mod_checksimul(UNUSED void *instance, UNUSED REQUEST *request)
{
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_lua = {
	RLM_MODULE_INIT,
	"lua",
	RLM_TYPE_THREAD_SAFE,		/* type */
	sizeof(rlm_lua_t),
	module_config,
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		mod_authenticate,		/* authentication */
		mod_authorize,		/* authorization */
		mod_preacct,		/* preaccounting */
		mod_accounting,		/* accounting */
		mod_checksimul,		/* checksimul */
		NULL,				/* pre-proxy */
		NULL,				/* post-proxy */
		NULL				/* post-auth */
#ifdef WITH_COA
		,
		NULL,				/* recv-coa */
		NULL				/* send-coa */
#endif
	},
};

