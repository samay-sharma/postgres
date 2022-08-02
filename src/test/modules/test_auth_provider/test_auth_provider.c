/* -------------------------------------------------------------------------
 *
 * test_auth_provider.c
 *			example authentication provider plugin
 *
 * Copyright (c) 2022, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		contrib/test_auth_provider/test_auth_provider.c
 *
 * -------------------------------------------------------------------------
 */

#include "postgres.h"
#include "fmgr.h"
#include "libpq/auth.h"
#include "libpq/libpq.h"
#include "libpq/scram.h"

PG_MODULE_MAGIC;

void _PG_init(void);

static char *get_encrypted_password_for_user(char *user_name);

/*
 * List of usernames / passwords to approve. Here we are not
 * getting passwords from Postgres but from this list. In a more real-life
 * extension, you can fetch valid credentials and authentication tokens /
 * passwords from an external authentication provider.
 */
char credentials[3][3][50] = {
	{"bob","alice","carol"},
	{"bob123","alice123","carol123"}
};

static int TestAuthenticationCheck(Port *port)
{
	int result = STATUS_ERROR;
	char *real_pass;
	const char *logdetail = NULL;

	real_pass = get_encrypted_password_for_user(port->user_name);
	if (real_pass)
	{
		result = CheckSASLAuth(&pg_be_scram_mech, port, real_pass, &logdetail);
		pfree(real_pass);
	}

	if (result == STATUS_OK)
		set_authn_id(port, port->user_name);

	return result;
}

/*
 * Get SCRAM encrypted version of the password for user.
 */
static char *
get_encrypted_password_for_user(char *user_name)
{
	char *password = NULL;
	int i;
	for (i=0; i<3; i++)
	{
		if (strcmp(user_name, credentials[0][i]) == 0)
		{
			password = pstrdup(pg_be_scram_build_secret(credentials[1][i]));
		}
	}

	return password;
}

static const char *TestAuthenticationError(Port *port)
{
	char *error_message = (char *)palloc (100);
	sprintf(error_message, "Test authentication failed for user %s", port->user_name);
	return error_message;
}

void
_PG_init(void)
{
	RegisterAuthProvider("test", TestAuthenticationCheck, TestAuthenticationError);
}
