from distutils.core import setup, Extension

module1 = Extension('demo', sources = ['T3P.c'])

setup (name = 'WrapperRaw',
       version = '1.0',
       description = 'This is wrapper package',
       author = 'Gianmarco Accordi',
       author_email = '10587213@polimi.it',
       url = '',
       long_description = '''
This is really just a demo package.
''',
       ext_modules = [module1])
