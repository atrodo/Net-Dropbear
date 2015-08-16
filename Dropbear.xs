#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "includes.h"
#include "dbutil.h"
#include "session.h"
#include "buffer.h"
#include "signkey.h"
#include "runopts.h"
#include "dbrandom.h"
#include "crypto_desc.h"
#include "libdropbear.h"

typedef void * dropbear__xs;
typedef void * Net_Dropbear_XS;

int _get_bool(SV *self, char *method)
{
	int count;
	int result;
	SV *option;

	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(self);
	PUTBACK;
	count = call_method(method, G_SCALAR);
	SPAGAIN;

	if (count != 1)
	  croak(Perl_form("Too much result from %s\n", method));

	option = POPs;
	result = SvTRUE(option);

	PUTBACK;
	FREETMPS;
	LEAVE;

	return result;
}

SV* hooks_self;
int hooks_on(const char *hook, AV* args)
{
    int RETVAL;
    int len, i;

    dSP;

    ENTER;
    SAVETMPS;

    if (hooks_self == NULL)
        hooks_self = &PL_sv_undef;

    PUSHMARK(SP);
    XPUSHs(hooks_self);
    XPUSHs(sv_2mortal(newSVpv(hook, 0)));

    len = av_len(args) + 1;

    for(i = 0; i < len; i++)
    {
        SV ** elem = av_fetch(args, i, 0);
        if ( elem != NULL )
          XPUSHs(*elem);
        else
          XPUSHs(&PL_sv_undef);
    }

    PUTBACK;
    int count = call_method("auto_hook", G_EVAL | G_SCALAR);
    SPAGAIN;

    if (SvTRUE(ERRSV))
    {
        dropbear_log(LOG_DEBUG, "Error calling %s: %s\n", hook, SvPV_nolen(ERRSV));
        RETVAL = DROPBEAR_FAILURE;
    }
    else
    {
        RETVAL = POPi;
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    return RETVAL;
}

int hooks_on_username(const char* username)
{
    ENTER;
    SAVETMPS;

    AV* args = newAV();

    av_push(args, sv_2mortal(newSVpv(username, 0)));
    int RETVAL = hooks_on("on_username", args);

    FREETMPS;
    LEAVE;

    return RETVAL;
}

int hooks_on_passwd_fill(struct AuthState auth)
{
    ENTER;
    SAVETMPS;

    AV* args = newAV();

//    av_push(args, sv_2mortal(newSVpv(auth, 0)));
    int RETVAL = hooks_on("on_passwd_fill", args);

    FREETMPS;
    LEAVE;

    return RETVAL;
}

int hooks_on_shadow_fill(char** crypt_password)
{
    ENTER;
    SAVETMPS;

    AV* args = newAV();

    av_push(args, sv_2mortal(newSVpv("", 0)));
    int RETVAL = hooks_on("on_shadow_fill", args);

    SV** arg = av_fetch(args, 0, 0);
    if ( arg != NULL )
    {
      *crypt_password = m_strdup(SvPV_nolen(*arg));
      warn("1 %s\n", SvPV_nolen(*arg));
      warn("2 %s\n", *crypt_password);
    }

    FREETMPS;
    LEAVE;
      warn("3 %s\n", *crypt_password);

    return RETVAL;
}

MODULE = Net::Dropbear	PACKAGE = Net::Dropbear::XS

BOOT:
{
    HV *stash = gv_stashpv("Net::Dropbear::XS", 0);

    newCONSTSUB(stash, "DROPBEAR_SUCCESS", newSViv (DROPBEAR_SUCCESS));
    newCONSTSUB(stash, "DROPBEAR_FAILURE", newSViv (DROPBEAR_FAILURE));
}

void
gen_key(const char* filename, enum signkey_type keytype=DROPBEAR_SIGNKEY_RSA, int bits=2048)
    CODE:
        dropbear_gen_key(keytype, bits, filename);

void
svr_main(CLASS)
	SV *CLASS = NO_INIT
    PROTOTYPE: $
    CODE:
	dropbear_run();
	/* Never Returns */

void
setup_svr_opts(CLASS, ref)
	SV *CLASS = NO_INIT
	SV * ref
    PROTOTYPE: $$
    CODE:
	dropbear_init();
        svr_opts.forkbg         = _get_bool(ref, "forkbg");
	svr_opts.usingsyslog    = _get_bool(ref, "usingsyslog");
	svr_opts.inetdmode      = _get_bool(ref, "inetdmode");
        svr_opts.norootlogin    = _get_bool(ref, "norootlogin");
        svr_opts.noauthpass     = _get_bool(ref, "noauthpass");
        svr_opts.norootpass     = _get_bool(ref, "norootpass");
        svr_opts.allowblankpass = _get_bool(ref, "allowblankpass");
        svr_opts.delay_hostkey  = _get_bool(ref, "delay_hostkey");
#ifdef DO_MOTD
        svr_opts.domotd = _get_bool(ref, "domotd");
#endif
#ifdef ENABLE_SVR_REMOTETCPFWD
        svr_opts.noremotetcp = _get_bool(ref, "noremotetcp");
#endif
#ifdef ENABLE_SVR_LOCALTCPFWD
        svr_opts.nolocaltcp = _get_bool(ref, "nolocaltcp");
#endif

        hooks_self = ref;
        hooks.on_username = hooks_on_username;
        hooks.on_passwd_fill = hooks_on_passwd_fill;
        hooks.on_shadow_fill = hooks_on_shadow_fill;

        int count, i;
        SSize_t len;
        SV * ref_result;

        ENTER;
        SAVETMPS;

        PUSHMARK(SP);
        XPUSHs(ref);
        PUTBACK;
        warn("+++\n");
        count = call_method("addrs", G_SCALAR);
        warn("---\n");
        SPAGAIN;

        if (count != 1)
          croak(Perl_form("Too much result from %s\n", "addr"));

        ref_result = POPs;

        if (!SvROK(ref_result) || SvTYPE(SvRV(ref_result)) != SVt_PVAV)
          croak("$self->addrs did not return an array");

        PUTBACK;

        AV* addrs = (AV*)SvRV(ref_result);
        len = av_tindex(addrs);

        for (i = 0; i <= len; i++)
        {
          SV** addr = av_fetch(addrs, i, 0);
          if ( addr != NULL )
          {
            warn("%s\n", SvPV_nolen(*addr));
            dropbear_add_svr_addr(SvPV_nolen(*addr));
          }
        }

	PUSHMARK(SP);
	XPUSHs(ref);
	PUTBACK;
	count = call_method("keys", G_SCALAR);
	SPAGAIN;

	if (count != 1)
	  croak(Perl_form("Too much result from %s\n", "addr"));

	ref_result = POPs;

        if (!SvROK(ref_result) || SvTYPE(SvRV(ref_result)) != SVt_PVAV)
          croak("$self->addr did not return an array");

	PUTBACK;

        AV* svr_keys = (AV*)SvRV(ref_result);
        len = av_len(svr_keys);

        for (i = 0; i <= len; i++)
        {
          SV** key = av_fetch(svr_keys, i, 0);
          if ( key != NULL )
          {
            warn("%s\n", SvPV_nolen(*key));
            dropbear_add_svr_key(SvPV_nolen(*key));
          }
        }

	FREETMPS;
	LEAVE;


Net_Dropbear_XS *
new(CLASS)
        char *CLASS = NO_INIT
    PROTOTYPE: $
    CODE:
	Newxz(RETVAL, 1, Net_Dropbear_XS);
    OUTPUT:
        RETVAL

MODULE = Net::Dropbear	PACKAGE = Net_Dropbear_XSPtr

char *
bannerfile(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	char * __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.bannerfile = __value;
	RETVAL = svr_opts.bannerfile;
    OUTPUT:
	RETVAL

int
forkbg(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.forkbg = __value ? 1 : 0;
	RETVAL = svr_opts.forkbg;
    OUTPUT:
	RETVAL

int
usingsyslog(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.usingsyslog = __value ? 1 : 0;
	RETVAL = svr_opts.usingsyslog;
    OUTPUT:
	RETVAL

=c

char *
ports(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	char * __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.ports = __value;
	RETVAL = svr_opts.ports;
    OUTPUT:
	RETVAL

unsigned int
portcount(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	unsigned int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.portcount = __value;
	RETVAL = svr_opts.portcount;
    OUTPUT:
	RETVAL

char *
addresses(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	char * __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.addresses = __value;
	RETVAL = svr_opts.addresses;
    OUTPUT:
	RETVAL

=cut

int
inetdmode(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.inetdmode = __value ? 1 : 0;
	RETVAL = svr_opts.inetdmode;
    OUTPUT:
	RETVAL


int
domotd(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
#ifdef DO_MOTD
	if (items > 1)
	    svr_opts.domotd = __value ? 1 : 0;
	RETVAL = svr_opts.domotd;
#endif
    OUTPUT:
	RETVAL


int
norootlogin(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.norootlogin = __value ? 1 : 0;
	RETVAL = svr_opts.norootlogin;
    OUTPUT:
	RETVAL

int
noauthpass(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.noauthpass = __value ? 1 : 0;
	RETVAL = svr_opts.noauthpass;
    OUTPUT:
	RETVAL

int
norootpass(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.norootpass = __value ? 1 : 0;
	RETVAL = svr_opts.norootpass;
    OUTPUT:
	RETVAL

int
allowblankpass(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.allowblankpass = __value ? 1 : 0;
	RETVAL = svr_opts.allowblankpass;
    OUTPUT:
	RETVAL


int
noremotetcp(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
#ifdef ENABLE_SVR_REMOTETCPFWD
	if (items > 1)
	    svr_opts.noremotetcp = __value ? 1 : 0;
	RETVAL = svr_opts.noremotetcp;
#endif
    OUTPUT:
	RETVAL



int
nolocaltcp(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
#ifdef ENABLE_SVR_LOCALTCPFWD
	if (items > 1)
	    svr_opts.nolocaltcp = __value ? 1 : 0;
	RETVAL = svr_opts.nolocaltcp;
#endif
    OUTPUT:
	RETVAL


=c

sign_key *
hostkey(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	sign_key * __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.hostkey = __value;
	RETVAL = svr_opts.hostkey;
    OUTPUT:
	RETVAL

=cut

int
delay_hostkey(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.delay_hostkey = __value ? 1 : 0;
	RETVAL = svr_opts.delay_hostkey;
    OUTPUT:
	RETVAL

=c

char *
hostkey_files(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	char * __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.hostkey_files = __value;
	RETVAL = svr_opts.hostkey_files;
    OUTPUT:
	RETVAL

int
num_hostkey_files(THIS, __value = NO_INIT)
	Net_Dropbear_XS * THIS
	int __value
    PROTOTYPE: $;$
    CODE:
	if (items > 1)
	    svr_opts.num_hostkey_files = __value;
	RETVAL = svr_opts.num_hostkey_files;
    OUTPUT:
	RETVAL

=cut
