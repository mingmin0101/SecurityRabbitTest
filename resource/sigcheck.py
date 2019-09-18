#!/usr/bin/env python
"""sigcheck - remember where a signature was seen

2004-2005 Martin Renold, public domain, no warranty etc.

TODO:
- are fingerprints really unique? probably yes because it's all you
  check on a keysigning party
- make really sure keys are re-fetched from time to time (to notice
  revoked keys); well maybe gpg does this for us already?
- some interactive features (ask for notes to add to a new key etc.)
- maybe more control over exit code for non-interactive use?
"""

# add new fingerprints to the config/history file automatically
autoadd_keys = 1 
# whether to print the key description if no comment is available
print_key_desc = 0

# gpg command and arguments
pgp_verify = 'gpg --no-auto-check-trustdb --with-fingerprint --no-verbose --batch --output - --verify'
# older gpg versions don't support --no-auto-check-trustdb
#pgp_verify = 'gpg --with-fingerprint --no-verbose --batch --output - --verify'

import sys, os, popen2, string, time
# TODO: check that this file is not world-writeable
configfile = os.path.join(os.getenv('HOME'), '.sigcheck')

defaultconfig = """You can simply add/change the fingerprints/comments.
Comments before the first timestamp will not scroll down.

"""

def unify_fingerprint(s):
    "returns the fingerprint string in unified form, or None"
    partlen = None
    fp = ''
    for part in s.split():
        if partlen is None:
            partlen = len(part)
        elif partlen != len(part):
            return None
        for ch in part:
            if ch not in string.hexdigits:
                return None
            fp += ch
    if len(fp) < 20:
        return None
    return fp.upper()

def get_timestamp(s):
    "returns the YYYY-MM-DD timestamp at the start of the string in days, or None"
    try:
        return time.mktime(time.strptime(s[:10], '%Y-%m-%d'))
    except ValueError:
        return None

class Config:
    def __init__(self, filename):
        self.filename = filename
    def ReadFile(self):
        # split the file into sections at each fingerprint line
        lineno = 0
        seen_fp = []
        sections = []
        sections.append([])
        for line in open(self.filename).readlines():
            lineno += 1
            fp = unify_fingerprint(line)
            if fp:
                sections.append([])
                if fp in seen_fp:
                    print 'Duplicate fingerprint at line', lineno, 'in', configfile + ':'
                    print line,
                    sys.exit(2)
                seen_fp.append(fp)
            sections[-1].append(line)
        # parse the individual sections
        self.keys = []
        self.header = sections[0]
        for lines in sections[1:]:
            self.keys.append(Key(lines))
    def WriteFile(self):
        f = open(self.filename, 'w')
        f.write(''.join(self.header))
        for key in self.keys:
            f.write(key.GetString())
    def GetKey(self, fingerprint):
        fp = unify_fingerprint(fingerprint)
        for key in self.keys:
            if key.fp == fp: return key
        return None
    def AddKey(self, key):
        self.keys.append(key)
        
class Key:
    def __init__(self, lines):
        lines_nonempty = []
        for line in lines: 
            if line.strip(): lines_nonempty.append(line)
        lines = lines_nonempty
        self.fingerprint = lines[0]
        self.fp = unify_fingerprint(self.fingerprint)
        lines = lines[1:]
        self.comments = []
        while lines and get_timestamp(lines[0]) is None:
            self.comments += lines[0]
            lines = lines[1:]
        self.timestamps = lines
    def AddTimestamp(self, note):
        note = time.strftime('%Y-%m-%d ') + note + '\n'
        for line in self.timestamps:
            if line[10:] == note[10:]:
                return
        self.timestamps.insert(0, note)
    def GetString(self):
        return self.fingerprint + ''.join(self.comments) + ''.join(self.timestamps) + '\n'
    def Print(self, key_desc=None, max_timestamps=5):
        if self.comments:
            print ''.join(self.comments),
        elif print_key_desc:
            # user had not yet commented the key
            if key_desc:
                print 'Unverified: "' + key_desc + '"'
                #print 'From unverified key "' + key_desc + '", fingerprint:'
                #print self.fingerprint.strip()
            else:
                print 'From unverified descriptionless key, fingerprint:'
                print self.fingerprint.strip()
        lines = self.timestamps
        if len(lines) > max_timestamps + 1:
            lines = lines[:max_timestamps]
            lines.append('... %d more entries\n' % (len(self.timestamps) - len(lines)))
        if lines:
            print ''.join(lines),
        elif not self.comments:
            print 'Never seen this signature before.'

if not os.path.exists(configfile):
    open(configfile, 'w').write(defaultconfig)
    print 'created', configfile
config = Config(configfile)
config.ReadFile()

mail = None
filename_text = None
if len(sys.argv) == 2 and sys.argv[1] == '--mail':
    # verify mail on stdin
    import email
    mail = email.message_from_file(sys.stdin)
    o, i, e = popen2.popen3(pgp_verify.split())
    # FIXME: check is_multipart
    i.write(mail.get_payload(decode=True))
    i.close()
elif len(sys.argv) == 2 and not sys.argv[1].startswith('-'):
    # verify .sig file (or .asc or .sign or whatever it's called)
    filename_signature = sys.argv[1]
    (filename_datafile, ext) = os.path.splitext(filename_signature)
    filename_text = os.path.basename(filename_datafile)
    if not os.path.exists(filename_signature):
        print 'File', filename_signature, 'does not exist!'
        sys.exit(2)
    if not os.path.exists(filename_datafile):
        print 'File', filename_datafile, 'does not exist!'
        print 'Please give the name of the signature file.'
        sys.exit(2)
    o, i, e = popen2.popen3(pgp_verify.split() + [filename_signature, filename_datafile])
else:
    print 'Only one argument is accepted for now: the .sig file to verify.'
    print 'Or --mail to verify an email on stdin.'
    sys.exit(2)

output = e.read()
status = os.wait()[1]
exitcode = os.WEXITSTATUS(status)
#print output
if exitcode == 1:
    print 'BAD SIGNATURE'
elif exitcode == 0:
    fingerprint = output.split('=')[-1].strip()
    if not unify_fingerprint(fingerprint):
      # older gpg version
      fingerprint = output.strip().split('\n')[-1].split(':')[-1]
    if not unify_fingerprint(fingerprint):
      print 'fingerprint=', fingerprint
      print 'Could not parse gpg fingerprint from output:'
      print output
      sys.exit(2)
    key = config.GetKey(fingerprint)
    if not key and autoadd_keys:
        key = Key([fingerprint.strip() + '\n'])
        config.AddKey(key)
        print 'New key added to', configfile
    if key:
        print 'Correct signature, history:'
        key.Print(key_desc=output.split('"')[1])
	if filename_text:
            comment = 'File ' + filename_text
	else:
	    assert mail
	    comment = 'Subject: ' + mail['subject']
	    if len(comment) + len('YYYY-MM-DD ') > 79:
		comment = comment[:76 - len('YYYY-MM-DD ')] + '...'
        key.AddTimestamp(comment)
	#print 'New comment:', comment
        config.WriteFile()

        # FIXME: if the user has commented "BAD KEY" this will still result in exit code 0
        if not key.comments: exitcode = 1
    else:
        print 'Unknown signature, fingerprint:'
        print fingerprint
        exitcode = 1
else:
    print sys.argv[0] + ': gpg returned with strange exit code', exitcode
    print output
sys.exit(exitcode)

