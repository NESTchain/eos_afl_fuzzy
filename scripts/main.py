import os
import shutil
import sys
from hashlib import md5
from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter
import time
import platform
import asyncio
import concurrent.futures

wavm_results = {}

async def run_command2(n, *args):
    my_env = { **os.environ, 'LIBC_FATAL_STDERR_': 'yes' }  # libc default prints error messages to /dev/tty
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, env = my_env)

    # print('Started: ', n, ', ', args, '(pid = ' + str(process.pid) + ')')

    future = asyncio.ensure_future(process.communicate())
    done, pending = await asyncio.wait([future], timeout = 5)
    if pending:
        if process.returncode is None:
            print("timeout, killing process: ", args[1])
            try:
                process.kill()
            except ProcessLookupError:
                pass

    stdout, stderr = await future

    # if process.returncode == 0:
    #     print('Done: ', n, ', ', args, '(pid = ' + str(process.pid) + ')')
    # else:
    #     print('Failed: ', n, ', ', args, '(pid = ' + str(process.pid) + ')')

    results = [args[1], stdout, stderr, process.returncode]
    wavm_results[n] = results;



class FileDuplicateFinder:
    # 0 for matching at the beginning, 1 for matching at any position
    false_positives = [
        ["Error validating WebAssembly binary file", 0],
        ["Error parsing WebAssembly text file", 0],
        ["Error deserializing WebAssembly binary file", 0],
        ["terminate called after throwing an instance of 'std::runtime_error'", 0],
        ["Runtime exception: reached unreachable code", 0],
        ["handle hardware trap", 0],
        ["Module does not export main function", 0],
        ["Runtime exception: out of memory", 0],
        ["Runtime exception: invalid floating point operation", 0],
        ["Runtime exception: undefined function table element", 0],
        ["Runtime exception: integer divide by zero or signed integer overflow", 0],
        ["wavm: malloc.c", 0],
        ["Module does not declare a default memory object to put arguments in", 0],
        ["WebAssembly function requires 1 argument(s), but only 0 or 2 can be passed!", 0],
        ["corrupted size vs. prev_size", 1],
        ["realloc(): invalid next size", 1]
    ]

    def __init__(self, exe_name, search_dir):
        self.exe_name = exe_name
        self.search_dir = search_dir

        self.false_positives_map = {}
        for v in self.false_positives:
            pattern_str, match_any = v
            self.false_positives_map[pattern_str] = [ 0, [] ]

    def is_false_positive(self, error, file):
        for v in self.false_positives:
            pattern_str, match_any = v
            len_pattern = len(pattern_str)
            len_error = len(error)
            if (len_error < len_pattern):
                continue
            bytes_pattern = bytes(pattern_str, encoding = "utf-8");

            if match_any == 0:  #  matching at the beginning
                bytes_error = error[0 : len_pattern]
                if (bytes_pattern == bytes_error):
                    self.false_positives_map[pattern_str][0] += 1
                    self.false_positives_map[pattern_str][1].append(file)
                    return True
            else:          # matching at any position
                for k in range(0, len_error - len_pattern):
                    bytes_error = error[k : k + len_pattern]
                    if (bytes_pattern == bytes_error):
                        self.false_positives_map[pattern_str][0] += 1
                        self.false_positives_map[pattern_str][1].append(file)
                        return True

        return False


    def find_unique_contents(self):

        md5map = {}
        for path, _, files in os.walk(self.search_dir):
            for filename in files:
                if filename.endswith("README.txt"):
                    continue
                filepath = os.path.join(path, filename)
                if filepath.find("/crashes/") > 0 and os.path.isfile(filepath):
                    with open(filepath, mode='rb') as openfile:
                        filehash = md5(openfile.read()).hexdigest()
                    md5map.setdefault(filehash, []).append(filepath)

        total = 0
        k = 0
        for md5hash, flist in md5map.items():
            # print( str(k) + ", md5: " + str(md5hash))
            j = 0
            for fpath in flist:
                # print( "    " + fpath)
                j += 1
                total += 1
            k += 1
        print( "total " + str(total) + " files found, ", len(md5map),  " unique md5.")

        event_loop = asyncio.get_event_loop()

        try:
            futures = []

            N = 5
            n = 0
            k = 0;
            for md5hash, flist in md5map.items():
                n += 1
                k += 1

                args = [self.exe_name, flist[0]]
                futures.append(asyncio.ensure_future(run_command2(n, *args)))

                if k >= N:
                    event_loop.run_until_complete(asyncio.gather(*futures))
                    futures.clear()
                    k = 0;

                # if (n > 2000):
                #     break

            if len(futures) > 0:
                event_loop.run_until_complete(asyncio.gather(*futures))
        finally:
            event_loop.close()


        succeeded = []
        empty_error = []
        unknown_error = []

        m = 0;
        sorted_dict = dict(sorted(wavm_results.items()))
        print("total running results: ", len(sorted_dict))
        for k, v in sorted_dict.items():
            fname, stdout, stderr, exitcode = v
            if (exitcode == 0):
                succeeded.append(fname)
                continue

            if (stderr is None):
                empty_error.append(fname)
                continue

            if (len(stderr) == 0):
                empty_error.append(fname)
                continue

            if self.is_false_positive(stderr, fname):
                continue

            unknown_error.append(fname)
            m += 1
            print("file ", m, ", ", fname);
            if (stdout is not None):
                print(stdout)
            if (stderr is not None):
                print(stderr)

        print("count = ", len(succeeded), ", running succeeded")

        print("count = ", len(empty_error), ", empty error info")
        for fname in empty_error:
            print("    ", fname)

        for error_str, v in self.false_positives_map.items():
            print("count = ", len(v[1]), ", error = ", error_str)
            # for fname in v[1]:
            #     print("    ", fname)


def main(argv=None):
    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    # Setup argument parser
    parser = ArgumentParser(description="AFL crash/hang analyzer)",
                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument("-e", "--exe", dest="exe", action="store",
                        help="Exe name to run")
    parser.add_argument("-d", "--dir", dest="dir", action="store",
                        help="Directory name to process")

    args = parser.parse_args()

    if args.exe and args.dir:

        fdf = FileDuplicateFinder(args.exe, args.dir)
        start = time.time()

        if platform.system() == 'Windows':
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

        fdf.find_unique_contents()

        end = time.time()
        rounded_end = ('{0:.4f}'.format(round(end - start, 4)))
        print('Script ran in about', str(rounded_end), 'seconds')

    return 0


if __name__ == "__main__":
    sys.exit(main())