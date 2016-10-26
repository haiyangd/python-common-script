import pexpect

PROMPT = ['# ', '>>> ', '> ', '. ', '\$ ']

def send_command(child, cmd):
    child.expect(']#')
    child.sendline("which ls")
#    print pexpect.EOF
    child.expect(']#')
    print child.before
#    print child.after
    print "hadong"

def connect(user, host, password):
    ssh_newkey = 'Are you sure you want to continue connecting (yes/no)?'
    connStr = 'ssh ' + user + '@' + host
    child = pexpect.spawn(connStr)
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey, \
                        '[P|p]assword:'])
    if ret == 0:
        print '[-] Error Connecting'
        return
    if ret == 1:
        child.sendline('yes')
        ret = child.expect([pexpect.TIMEOUT, \
                            '[P|p]assword:'])
        if ret == 0:
            print '[-] Error Connecting'
            return
    child.sendline(password)
#    child.expect(PROMPT)
    return child

def main():
    host = '182.254.246.127'
    user = 'root'
    password = 'redhat123'
    child = connect(user, host, password)
    send_command(child, 'echo "hadong"')

if __name__ == '__main__':
    main()
