from __future__ import print_function

import re
import argparse

def get_args():
    parser = argparse.ArgumentParser(
        description='Generate a libsodium version.h file')

    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-c', '--configure-ac', required=True)
    parser.add_argument('input')

    return parser.parse_args()

def get_version_info_from_configure_ac(path):
    ac_init_re = re.compile('AC_INIT\((.*?)\)', re.MULTILINE | re.DOTALL)
    maj_min_re = re.compile('^SODIUM_LIBRARY_VERSION_(.*?)=(.*)$', re.MULTILINE)

    version = None
    major   = None
    minor   = None

    with open(path, 'r') as f:
        the_whole_file = f.read()

        # match AC_INIT() arguments and split them on commas
        ac_init_args = ac_init_re.search(the_whole_file).group(1).split(',')
        version = ac_init_args[1].strip('[]')

        # findall(), in this case, returns a list of 2-tuples in the
        # form of [(key, value)] and dict() turns that into a
        # dictionary of {key: value}
        maj_min = dict(maj_min_re.findall(the_whole_file))
        major, minor = [maj_min[x] for x in ('MAJOR', 'MINOR')]

    return {
        'VERSION': version,
        'SODIUM_LIBRARY_VERSION_MAJOR':   major,
        'SODIUM_LIBRARY_VERSION_MINOR':   minor,
    }

def subst(in_string, subst_vars):
    sub_re = re.compile('@(.*?)@')

    def replace(matchobj):
        return subst_vars[matchobj.group(1)]

    return sub_re.sub(replace, in_string)

def main():
    args = get_args()
    subst_vars = get_version_info_from_configure_ac(args.configure_ac)

    with open(args.output, 'w') as outfile:
        with open(args.input, 'r') as infile:
            outfile.write(subst(infile.read(), subst_vars))

if __name__ == '__main__':
    main()
