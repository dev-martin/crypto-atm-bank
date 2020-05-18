#! /usr/bin/env python

from __future__ import print_function
import pexpect
import sys
import os
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('proj_path')
parser.add_argument('-d', '--discard-stderr',
                    dest='discard',
                    action='store_true',
                    default=False,
                    help='discard STDERR, if you are using it for diagnostics'
                    )
parser.add_argument('-l', '--log-stdout',
                    dest='logstdout',
                    action='store_true',
                    default=False,
                    help='log to stdout instead of stderr'
                    )
parser.add_argument('--no-cleanup',
                    dest='nocleanup',
                    action='store_true',
                    default=False,
                    help='disable cleanup'
                    )
parser.add_argument('--no-ext',
                    dest='no_ext',
                    action='store_true',
                    default=False,
                    help='Invoke bank and atm with /path/to/file instead of /path/to/file.bank'
                    )
args = parser.parse_args()

proj_path = args.proj_path
discard = ''
if args.discard:
    discard = ' 2>/dev/null'

file_path = '/tmp/atm_test'

stderr = sys.stderr
stdout = sys.stdout
if 'buffer' in dir(stderr):
    stderr = stderr.buffer
if 'buffer' in dir(stdout):
    stdout = stdout.buffer

def spawn(cmd, **kwargs):
    retval = None
    try:
        retval = pexpect.spawn('/bin/bash', ['-c', cmd + discard], timeout=5, logfile=stderr
        if not args.logstdout else stdout, **kwargs)
        retval.ignorecase = True
        retval.setecho(False)
    except:
        pass
    return retval

def delfile(f):
    if os.path.exists(f):
        os.unlink(f)

def cleanup():
    if args.nocleanup:
        return
    delfile('{fp}.bank'.format(fp=file_path))
    delfile('{fp}.atm'.format(fp=file_path))

def check_exit(expected, actual):
    if expected != actual:
        print("Expected exit code {}, got {}".format(expected,actual))

def test_init(init_path):
    def expect_usage(c):
        c.expect('Usage:\tinit <filename>')
        c.close()
        check_exit(62, c.exitstatus)

    child = spawn('{path1}/bin/init'.format(path1=init_path))
    expect_usage(child)

    child = spawn('{path1}/bin/init foo bar'.format(path1=init_path))
    expect_usage(child)

    cleanup()
    
    child = spawn('{path1}/bin/init {path2}'.format(path1=init_path,path2=file_path))
    child.expect('Successfully initialized bank state')
    child.close()
    check_exit(0, child.exitstatus)
    
    child = spawn('{path1}/bin/init {path2}'.format(path1=init_path,path2=file_path))
    child.expect('Error:\tone of the files already exists')
    child.close()
    check_exit(63, child.exitstatus)
    
    cleanup()

def test_create_user(init_path):
    def expect_create_user_usage(c):
        c.expect('Usage:\tcreate-user <user-name> <pin> <balance>')
        c.expect('BANK: ')
    def expect_deposit_usage(c):
        c.expect('Usage:\tdeposit <user-name> <amt>')
        c.expect('BANK: ')

    init = spawn('{path1}/bin/init {path2}'.format(path1=init_path,path2=file_path))
    init.expect('Successfully initialized bank state')

    router = spawn('{path1}/bin/router'.format(path1=init_path))

    bank = spawn('{path1}/bin/bank {path2}.bank'.format(path1=init_path,path2=file_path))

    # some test cases for wrong create-user usage
    bank.expect('BANK: ')
    bank.sendline('create-user')
    expect_create_user_usage(bank)
    bank.sendline('create-user foo')
    expect_create_user_usage(bank)
    bank.sendline('create-user foo bar')
    expect_create_user_usage(bank)

    # one test case for correct create-user
    bank.sendline('create-user alice 1234 100')
    bank.expect('Created user alice')
    bank.expect('BANK: ')

    # some cases for balance
    bank.sendline('balance bob')
    bank.expect('No such user')
    bank.expect('BANK: ')
    
    bank.sendline('balance alice')
    bank.expect('\$100')
    bank.expect('BANK: ')

    # some cases for deposit
    bank.sendline('deposit alice 50')
    bank.expect('\$50 added to alice\'s account')
    bank.expect('BANK: ')

    bank.sendline('deposit alice -50')
    expect_deposit_usage(bank)

    init.close()
    router.close()
    bank.close()
    cleanup()
       
test_init(proj_path)
test_create_user(proj_path)
