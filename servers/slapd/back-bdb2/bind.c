/* bind.c - bdb2 backend bind and unbind routines */

#include "portable.h"

#include <stdio.h>

#include <ac/krb.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

#include <lutil.h>

#ifdef HAVE_KERBEROS
extern int	bdb2i_krbv4_ldap_auth();
#endif

static int
crypted_value_find(
	struct berval       **vals,
	struct berval       *v,
	int                 syntax,
	int                 normalize,
	struct berval		*cred
)
{
	int     i;
	for ( i = 0; vals[i] != NULL; i++ ) {
		if ( syntax != SYNTAX_BIN ) {
			int result;

#ifdef SLAPD_CRYPT
			ldap_pvt_thread_mutex_lock( &crypt_mutex );
#endif

			result = lutil_passwd(
				(char*) cred->bv_val,
				(char*) vals[i]->bv_val);

#ifdef SLAPD_CRYPT
			ldap_pvt_thread_mutex_unlock( &crypt_mutex );
#endif

			return result;

		} else {
                if ( value_cmp( vals[i], v, syntax, normalize ) == 0 ) {
                        return( 0 );
                }
        }
	}

	return( 1 );
}

static int
bdb2i_back_bind_internal(
    BackendDB		*be,
    Connection		*conn,
    Operation		*op,
    char		*dn,
    int			method,
    struct berval	*cred,
	char**	edn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry		*e;
	Attribute	*a;
	int		rc;
	char		*matched;
#ifdef HAVE_KERBEROS
	char		krbname[MAX_K_NAME_SZ + 1];
	AUTH_DAT	ad;
#endif

	Debug(LDAP_DEBUG_ARGS, "==> bdb2_back_bind: dn: %s\n", dn, 0, 0);

	*edn = NULL;

	/* get entry with reader lock */
	if ( (e = bdb2i_dn2entry_r( be, dn, &matched )) == NULL ) {
		/* allow noauth binds */
		if ( method == LDAP_AUTH_SIMPLE && cred->bv_len == 0 ) {
			/*
			 * bind successful, but return 1 so we don't
			 * authorize based on noauth credentials
			 */
			send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
			rc = 1;
		} else if ( be_isroot_pw( be, dn, cred ) ) {
			/* front end will send result */
			*edn = ch_strdup( be_root_dn( be ) );
			rc = 0;
		} else {
			send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, NULL );
			rc = 1;
		}
		if ( matched != NULL ) {
			free( matched );
		}
		return( rc );
	}

	*edn = ch_strdup( e->e_dn );

	/* check for deleted */

	switch ( method ) {
	case LDAP_AUTH_SIMPLE:
		if ( cred->bv_len == 0 ) {
			send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );

			/* stop front end from sending result */
			rc = 1;
			goto return_results;
		}

		if ( be_isroot_pw( be, dn, cred ) ) {
			/* front end will send result */
			if( *edn != NULL ) free( *edn );
			*edn = ch_strdup( be_root_dn( be ) );
			rc = 0;
			goto return_results;
		}

		if ( (a = attr_find( e->e_attrs, "userpassword" )) == NULL ) {
			send_ldap_result( conn, op, LDAP_INAPPROPRIATE_AUTH,
			    NULL, NULL );
			rc = 1;
			goto return_results;
		}

		if ( crypted_value_find( a->a_vals, cred, a->a_syntax, 0, cred ) != 0 )
		{
			send_ldap_result( conn, op, LDAP_INVALID_CREDENTIALS,
				NULL, NULL );
			rc = 1;
			goto return_results;
		}
		rc = 0;
		break;

#ifdef HAVE_KERBEROS
	case LDAP_AUTH_KRBV41:
		if ( bdb2i_krbv4_ldap_auth( be, cred, &ad ) != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, LDAP_INVALID_CREDENTIALS,
			    NULL, NULL );
			rc = 0;
			goto return_results;
		}
		sprintf( krbname, "%s%s%s@%s", ad.pname, *ad.pinst ? "."
		    : "", ad.pinst, ad.prealm );
		if ( (a = attr_find( e->e_attrs, "krbname" )) == NULL ) {
			/*
			 * no krbName values present:  check against DN
			 */
			if ( strcasecmp( dn, krbname ) == 0 ) {
				rc = 0; /* XXX wild ass guess */
				break;
			}
			send_ldap_result( conn, op, LDAP_INAPPROPRIATE_AUTH,
			    NULL, NULL );
			rc = 1;
			goto return_results;
		} else {	/* look for krbName match */
			struct berval	krbval;

			krbval.bv_val = krbname;
			krbval.bv_len = strlen( krbname );

			if ( value_find( a->a_vals, &krbval, a->a_syntax, 3 ) != 0 ) {
				send_ldap_result( conn, op,
				    LDAP_INVALID_CREDENTIALS, NULL, NULL );
				rc = 1;
				goto return_results;
			}
		}
		rc = 0;
		break;

	case LDAP_AUTH_KRBV42:
		send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
		/* stop front end from sending result */
		rc = 1;
		goto return_results;
#endif

	default:
		send_ldap_result( conn, op, LDAP_STRONG_AUTH_NOT_SUPPORTED,
		    NULL, "auth method not supported" );
		rc = 1;
		goto return_results;
	}

return_results:;
	/* free entry and reader lock */
	bdb2i_cache_return_entry_r( &li->li_cache, e );

	/* front end with send result on success (rc==0) */
	return( rc );
}


int
bdb2_back_bind(
    BackendDB		*be,
    Connection		*conn,
    Operation		*op,
    char		*dn,
    int			method,
    struct berval	*cred,
	char**	edn
)
{
	DB_LOCK         lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	if ( bdb2i_enter_backend_r( get_dbenv( be ), &lock ) != 0 ) {

		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		return( 1 );

	}

	ret = bdb2i_back_bind_internal( be, conn, op, dn, method, cred, edn );

	(void) bdb2i_leave_backend_r( get_dbenv( be ), lock );

	bdb2i_stop_timing( be->bd_info, time1, "BIND", conn, op );

	return( ret );
}


