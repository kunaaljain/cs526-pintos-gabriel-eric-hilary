#! /bin/sh -e

cd /tmp
mkdir $$
cd $$
mkdir bochs-2.2.6
tar xzf $SRCDIR/bochs-2.2.6.tar.gz
cd bochs-2.2.6
cat $PINTOSDIR/src/misc/bochs-2.2.6-ms-extensions.patch | patch -p1
cat $PINTOSDIR/src/misc/bochs-2.2.6-big-endian.patch | patch -p1
cat $PINTOSDIR/src/misc/bochs-2.2.6-jitter.patch | patch -p1
cat $PINTOSDIR/src/misc/bochs-2.2.6-triple-fault.patch | patch -p1
cat $PINTOSDIR/src/misc/bochs-2.2.6-solaris-tty.patch | patch -p1
cat $PINTOSDIR/src/misc/bochs-2.2.6-page-fault-segv.patch | patch -p1
cat $PINTOSDIR/src/misc/bochs-2.2.6-paranoia.patch | patch -p1
cat $PINTOSDIR/src/misc/bochs-2.2.6-gdbstub-ENN.patch | patch -p1
if test "`uname -s`" = "SunOS"; then
    cat $PINTOSDIR/src/misc/bochs-2.2.6-solaris-link.patch | patch -p1
fi
CFGOPTS="--with-x --with-x11 --with-term --with-nogui --prefix=$DSTDIR"
mkdir plain &&
        cd plain && 
        ../configure $CFGOPTS --enable-gdb-stub && 
        make && 
        make install &&
        cd ..
mkdir with-dbg &&
        cd with-dbg &&
        ../configure --enable-debugger $CFGOPTS &&
        make &&
        cp bochs $DSTDIR/bin/bochs-dbg &&
        cd ..
