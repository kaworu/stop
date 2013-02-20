# stop - Sysctl's htop

stop is a fork of htop (http://htop.sourceforge.net/) ported to FreeBSD's sysctl(3) interface.

## Why stop ?

While htop does compile and run under FreeBSD, it is only able to use /proc and
/sys virtual filesystem to retrieve system informations. The problem is
twofold; first the Linux /proc compatibility under FreeBSD is quite old - laggy
and incomplete (it was based on the Linux kernel 2.4 at the time of writting
the first bits) and secondly htop is badly crashing under some conditions (for
example the battery status display made it crash every time).

stop is a proof of concept to port htop using FreeBSD's sysctl. Then it should
define a common interface and rewrite htop's backend using a generic interface
and a collection of implementations (with already Linux and FreeBSD available),
easing porting htop to other OSes. Sadly this part hasn't yet been started, due
to the lack of collaboration of the htop author(s).
