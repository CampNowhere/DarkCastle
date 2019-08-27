import sys, subprocess, getpass, os

# Must have DarkCastle installed in your path for this to work

algorithm = 'uvajda'
extension = '.enc'
try:
    mode = sys.argv[1]
except IndexError as ier:
    print "Castle Vault v0.1\n"
    print "python castlev.py <e/d>"
    exit(1)
progname = sys.argv[0]
key = getpass.getpass()

def sumencs(dirl):
    files = dirl.split()
    s = len(files)
    count = 0
    for f in files:
        ext = f[len(f) - 4:]
        if ext == extension and f != progname and f != '':
            count += 1
        elif f == progname:
            s = s - 1
    if s == count:
        return True
    else:
        return False

if mode == "e":
    cmd = ['ls']
    dirl = subprocess.check_output(cmd)
    if sumencs(dirl) == True:
        print "Directory encrypted. Aborting..."
        exit(1)
    files = dirl.split()
    for f in files:
        fname = f.split("\n")[0]
        fsize = os.path.getsize(fname)
        if fsize > 0:
            if fname != progname:
                fnameenc = fname + ".enc"
                cmd = ['castle', algorithm, '-e', fname, fnameenc, key]
                out = subprocess.check_output(cmd)
                cmd = ['rm', fname]
                out = subprocess.check_output(cmd)
                print fname
        else:
            print fname + " doesn't meet the minimum filesize requirement. 1 byte"

if mode == "d":
    cmd = ['ls']
    dirl = subprocess.check_output(cmd)
    if sumencs(dirl) == False:
        print "Directory not encrypted. Aborting..."
        exit(1)
    files = dirl.split()
    for f in files:
        fname = f.split("\n")[0]
        fsize = os.path.getsize(fname)
        if fsize > 0:
            if fname != progname:
                fnametmp = fname.split('.')
                fnameenc = fnametmp.pop(0)
                for x in xrange(len(fnametmp)-1):
                    fnameenc += "." + fnametmp[x]
                cmd = ['castle', algorithm, '-d', fname, fnameenc, key]
                out = subprocess.check_output(cmd)
                if "Message" not in out:
                    cmd = ['rm', fname]
                    out = subprocess.check_output(cmd)
                    print fnameenc
                else:
                    print fnameenc + " had an issue."
        else:
            print fname + " doesn't meet the minimum filesize requirement. 1 bytes"

