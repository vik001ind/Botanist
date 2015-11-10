#!/usr/bin/python
#
#
# Created by Cory Pruce
#   RevEngdroid project
#
#   This program is used to unzip and parse
#   apk files for particular signatures for
#   toolchains that have been used. This
#   chain begins in the MainActivity's
#   onCreate method. Notably, the
#   System.loadLibrary function is of
#   interest due to the statement information
#   gain ratio being the most revealing. This
#   HexParse program then creates the signature
#   with the tapered levenshtein distance. The
#   file handling and parsing in this program
#   leverages the androguard framework.

import sys
import subprocess
from optparse import OptionParser
from androguard.core import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
from androguard.decompiler.decompiler import *
from androguard.session import Session
from androguard.util import *
from androguard.misc import *
from sigGen import SigGen

from r2.r_core import RCore
core = RCore()


class ELFSigGen(SigGen):

    def run(self, APKfile):        	
        # Obtain apk, classes.dex, and the classes.dex analysis
        a, d, dx = AnalyzeAPK(APKfile)

    # tie analysis to classes.dex
        d.set_vmanalysis(dx)

    # Create cross and data references
        d.create_xref()
        d.create_dref()

    # find the tools
        for method in d.get_methods():

        # find .so's
            so_files = []            
            if "loadLibrary" in method.get_source():
                rnames = self.find_so_files(method, a)

                for rname in rnames:
                    so = "lib" + rname + ".so"

                    if self.dump_files(so, a):
                        so_files.append(so)              

                # tag tools
                for so in so_files:
                    # .so found, find the init function
                    rname = so[3:-3] # remove 'lib' prefix and '.so' extension
                    func = self.get_init(rname, method, d, dx)
                    if func != '':
                        # init found, now find code in .so
                        print 'init', func, 'found.'
                        self.parse_elf_print_Sig(rname, func)
                    else:
                        print 'init', func, 'not found.'
                                
    
    @staticmethod
    def find_so_files(method, a):
        src = method.get_source() # get_real_names
        lines = src.split('\n')
        rnames = []
        for l in lines:
            if "loadLibrary" in l:
                # extract the .so real name
                last_lib = l.strip()[20:-3] # System.loadLibrary("");
                rnames.append(last_lib)
        return rnames


                                

    @staticmethod 
    def dump_files(so, a):
        for fname in a.get_files():

            if so in fname:
                so_file = a.get_file(fname)
                fd = open(so,"w")

                print >> fd, so_file
                fd.close()
                return True
        return False

    @staticmethod
    def get_stub_method(i, rname, type_sig, d, dx):
        func = ""
        
        if 'invoke' in i.get_name():
              
            #meth_call = get_method_from_instr(type_sig)
            meth_call = 'L' + type_sig.split('L', 1)[1] # starting from just method name 
            for n_method in get_NativeMethods(dx):           
                meth = n_method[0] + '->' + n_method[1] + n_method[2]
                                  
                if meth_call == meth:
                    # this is the first dynamic library call. From here, the
                    # analysis is transfered to finding this method's code
                    # in the .so.
                    # TODO: make sure that this native call is definitely
                    # the first call from THAT library


                    #print path[0], xrefto[0].name, n_method
                    cname = n_method[0][1:-1].replace('/', '_')  # remove OS type and semicolon
                    func = "Java_" + cname + "_" + n_method[1] #TODO: is Java always prepended?
                    # for mono: build's 'Java_mono_android_Runtime_init
                    #parse_elf(rname, func)
                    return 0, func
            
        return -1, func 
    
    @staticmethod
    def get_init(rname, method, d, dx):
        
        instructions = method.get_code().get_bc().get_instructions()
        rname_passed = False
        loadLib_passed = False

        for i in instructions:                
            type_sig = i.get_output()
      
            # first find the so
            if rname in type_sig:
                rname_passed = True
                continue
            # next, find the the dynamic load
            if rname_passed:
                if "loadLibrary" in type_sig:
                    loadLib_passed = True
                    print 'loadLibrary passed'
                    rname_passed = False
                    continue 
                        
            # after the lib load, the first native call to the loaded library will
            # be the "unpacking" routine that will be used as the signature
            func = ""            
            if loadLib_passed:       
                val, func = ELFSigGen.get_stub_method(i, rname, type_sig, d, dx)
                if val == 0:
                    print 'native stub found'
                    break
                elif val == 1:
                    print 'no stub found for dyna lib'
                    sys.exit(1)
                # else continue, first native call not found

        return func

    @staticmethod
    def get_func_start_addr(so, func):

        # use the nm tool to dump the func addrs
        # TODO: find out running the command is ok as opposed to a library call
        cmd_dump_func_addrs = "nm -D " + so
        process = subprocess.Popen(cmd_dump_func_addrs.split(), stdout=subprocess.PIPE)
        output = process.communicate()[0]

        # basically grep
        lines = output.split('\n')
        for line in lines:
            if func in line:
                print line
                return line.split()[0]
               
        return ''

    @staticmethod
    def get_sig(so, func, func_start_addr):

        # Capstone class for ARM architectures
        #md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        func_start_addr_int = int(func_start_addr, 16)
        func_start_addr_hex = hex(func_start_addr_int)
        so_file = open(so, 'rb')
        so_file_str = so_file.read()
        so_file.close()

        so_file = "./libmonodroid.so"
        core.bin.load (so_file, 0)
        print ("Supported archs: %d"%core.bin.narch)

        if core.bin.narch>1:
            for i in range (0,core.bin.narch):
                core.bin.select_idx (i)
                info = core.bin.get_info ()
                if info:
                    print ("%d: %s %s"%(i,info.arch,info.bits))

        # TODO: detect the architecture and set to that. Most will be 32-bit ARM
        # Load file in core
        core.config.set ("asm.arch", "arm");
        core.config.set ("asm.bits", "32");
        #core.config.set ("asm.bits", "64");

        f = core.file_open(so_file, False, 0)
        #core.bin_load (None)
        core.bin_load ("", 0)

        entry_point = func_start_addr_int

        print ("Entrypoint : 0x%x"%(entry_point))

        for i in xrange(0, 20):
            print ("%s"%(core.disassemble(entry_point+4*i).get_asm()))



    @staticmethod
    def parse_elf_print_Sig(so, func):
        so = 'lib' + so + '.so'
        func_start_addr = ELFSigGen.get_func_start_addr(so, func)

        if func_start_addr == '':
            print 'stub function not found in .so file'
            sys.exit(1)
        else:
            print 'stub func begins at ' + func_start_addr
            sig = ELFSigGen.get_sig(so, func, func_start_addr)




option_0 = {
    'name': ('-f', '--file'),
    'help': 'filename input (APK or android resources(arsc))',
    'nargs': 1
}
option_1 = {
    'name': ('-v', '--verbose'),
    'help': 'verbose mode',
    'action': 'count'
}

options = [option_0, option_1]

parser = OptionParser()
for option in options:
    param = option['name']
    del option['name']
    parser.add_option(*param, **option)


options, arguments = parser.parse_args()
sys.argv[:] = arguments

ELFSigGen().run(options.file)

