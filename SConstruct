import os
import subprocess
import sys
####Create a env object

vars = Variables()
vars.Add('TEST','Set to 1 to build unit tests',0)
vars.Add('DEBUG','Set to 1 to build debug',0)

env = Environment(ENV = os.environ,variables = vars,CPPDEFINES={'TEST':'${TEST}'})
Help(vars.GenerateHelpText(env))

BASE  = os.path.dirname(os.path.abspath("__file__"))
gtest_libs = os.path.join(BASE,'..','thirdparty','gtest-1.7.0','libgtest')
TransportLib_path = os.path.join(BASE,'..','lib')
env['BASE']=BASE

print "Running the autoconf system check"

conf = Configure(env)
if not os.path.exists("config.log"):
   
   pointer = conf.CheckTypeSize('int *')
   if pointer == 8:
      print "architecture\t....\t is 64 bit yes"
   else:
      print "32 bit not supported:",pointer
      exit(1)
   if not conf.CheckLib('pthread') or not conf.CheckLib('boost_system'):
      print "Library absent"
      exit(1)

gtest = gtest_libs+'/libgtest.a'

if not os.path.exists(gtest):
   print "build without gtest"
   env['CPPDEFINES']['TEST'] = 0


env['LIBS'] = []   
env['LIBPATH'] = [] 
   
if env['CPPDEFINES']['TEST'] != 0 and ARGUMENTS.get('TEST',0) != 0:
   env['LIBS'] = ['gtest']   
   env['LIBPATH'] = [gtest_libs] 
   print " Found Unit test Library ... yes"
   print "Append gtest path and library"
   

    
   ##### Add more checks here#####

###Begin the sub directory builds


Export('env')


proc = subprocess.Popen(sys.argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,cwd=TransportLib_path)
out,err = proc.communicate()
print out,err


SConscript(['Ipsec_Transport/TransportProto/SConscript',])

SConscript(['Ipsec_Transport/SConscript',])