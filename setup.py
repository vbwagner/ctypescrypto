from distutils.core import setup
import distutils.cmd
import sys, os

class MyTests(distutils.cmd.Command):
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        sys.path.insert(0, os.getcwd())
        import unittest
        result = unittest.TextTestResult(sys.stdout, True, True)
        suite = unittest.defaultTestLoader.discover("./tests")
        print ("Discovered %d test cases" % suite.countTestCases())
        result.buffer = True
        suite.run(result)
        print ("")
        if not result.wasSuccessful():
            if len(result.errors):
                print ("============ Errors disovered =================")
                for res in result.errors:
                    print (res[0], ":", res[1])

            if len(result.failures):
                print ("============ Failures disovered =================")
                for res in result.failures:
                    print (res[0], ":", res[1])
            sys.exit(1)
        else:
            print ("All tests successful")

setup(
    name="ctypescrypto",
    version="0.5",
    description="CTypes-based interface for some OpenSSL libcrypto features",
    author="Victor Wagner",
    author_email="vitus@wagner.pp.ru",
    url="https://github.com/vbwagner/ctypescrypto",
    packages=["ctypescrypto"],
    cmdclass={"test":MyTests}
)

