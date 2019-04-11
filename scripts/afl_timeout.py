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


class FileDuplicateFinder:

    def __init__(self, exe_name, job_limit):
        self.exe_name = exe_name
        self.job_limit = job_limit
        self.timeouted = []

    async def run_command_async(self, n, *args):
        my_env = {**os.environ, 'LIBC_FATAL_STDERR_': '1'}  # libc default prints error messages to /dev/tty
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=my_env)

        print('Started: ', n, ', ', args, '(pid = ' + str(process.pid) + ')')

        future = asyncio.ensure_future(process.communicate())
        done, pending = await asyncio.wait([future], timeout=20)
        if pending:
            if process.returncode is None:
                self.timeouted.append(args[1])
                # print("timeout, killing process: ", args[1])
                try:
                    process.kill()
                except ProcessLookupError:
                    pass

        stdout, stderr = await future

        if process.returncode == 0:
            print('Done: ', n, ', ', args, '(pid = ' + str(process.pid) + ')')
        else:
            print('Failed: ', n, ', exit code = ', process.returncode, ', ', args, '(pid = ' + str(process.pid) + ')')

        # results = [args[1], stdout, stderr, process.returncode]
        # self.wavm_results[n] = results;



    def find_unique_contents(self):

        items = [
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000314,sig:06,src:009250,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000280,sig:11,src:009516,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000271,sig:06,src:009713,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000433,sig:06,src:009990+009218,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000561,sig:06,src:009947,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000214,sig:06,src:009254,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000330,sig:11,src:009249,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000311,sig:06,src:009338+006239,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000325,sig:06,src:010434,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000541,sig:06,src:009768+009462,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000217,sig:11,src:000680+009338,op:splice,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000555,sig:06,src:009799,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000300,sig:11,src:009192+009338,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000199,sig:06,src:008142,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000356,sig:06,src:009618+009240,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000534,sig:06,src:009947,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000410,sig:11,src:010138,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000272,sig:11,src:010046+009338,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000379,sig:06,src:010371,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000505,sig:06,src:010369+009555,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000124,sig:11,src:007443,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000323,sig:06,src:009885,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000238,sig:06,src:009305,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000342,sig:06,src:009313,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000512,sig:06,src:009419,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000430,sig:06,src:009538+009797,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000574,sig:06,src:009842,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000310,sig:06,src:009245,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000279,sig:06,src:009564,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000497,sig:06,src:009737,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000208,sig:06,src:009438,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000316,sig:06,src:009722,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000446,sig:11,src:009757,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000371,sig:11,src:009438+009538,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000273,sig:06,src:009262,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000302,sig:11,src:009594,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000322,sig:06,src:009223,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000219,sig:06,sync:slave0,src:010088",
            "/home/happy/afl_chengang2/tmp/findings/slave5/crashes/id:000428,sig:06,src:006631,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000309,sig:06,src:009871,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000392,sig:06,src:009604,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000275,sig:06,src:010004+009609,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000323,sig:06,src:010258,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000593,sig:11,src:010279,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000660,sig:06,src:010072,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000508,sig:06,src:010110,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000329,sig:11,src:009937,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000419,sig:06,src:010019,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000579,sig:06,src:009909,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000511,sig:06,src:010216,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000486,sig:06,src:007106+010660,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000229,sig:06,src:009441,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000349,sig:11,src:009606+008739,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000433,sig:06,src:010520,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000289,sig:06,src:009869,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000425,sig:06,src:009969,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000288,sig:06,src:009373+009605,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000503,sig:11,src:009526,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000227,sig:11,src:009735,op:havoc,rep:8",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000645,sig:06,src:008887,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000501,sig:11,src:010071,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000344,sig:06,src:010224+008865,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000400,sig:06,src:009797+003140,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000580,sig:06,src:009996,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000290,sig:11,src:009415,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000616,sig:06,src:010181+006212,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000257,sig:06,src:009531,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000655,sig:06,src:009794,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000394,sig:06,src:008051+010053,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000104,sig:11,src:006838,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000261,sig:06,src:009912,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000339,sig:06,src:009927+009700,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000432,sig:06,src:009950,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000573,sig:06,src:010100,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000228,sig:06,sync:master,src:007172",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000271,sig:06,src:009773+003816,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000477,sig:11,src:006389+009350,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000369,sig:06,src:009772,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000458,sig:11,src:009637+009617,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000252,sig:06,src:009775,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000516,sig:06,src:010490,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000614,sig:06,src:010147,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000249,sig:11,src:005978+009622,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000591,sig:11,src:010172+009922,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000441,sig:06,src:009940,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000283,sig:11,src:000825+009428,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000336,sig:06,src:009464,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000305,sig:06,src:009549,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000237,sig:11,src:004887+009350,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000485,sig:11,src:009482,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000582,sig:06,src:010602,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000497,sig:06,src:009968,op:havoc,rep:8",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000581,sig:06,src:010533+009218,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000272,sig:11,src:009842,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000222,sig:11,sync:slave6,src:009923",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000315,sig:11,src:009363,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000638,sig:11,src:009827,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000398,sig:06,src:010051,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000298,sig:11,src:002103+009672,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000332,sig:11,src:010017+010029,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000046,sig:11,src:000096+003539,op:splice,rep:32",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000455,sig:06,src:010053,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000372,sig:06,src:008651,op:havoc,rep:64",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000280,sig:06,src:010166,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000314,sig:06,src:000156+009834,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000387,sig:06,src:010044,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000297,sig:06,src:009648,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000633,sig:06,src:009781,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000381,sig:06,src:009519+009350,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000482,sig:11,src:009422,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000293,sig:06,src:009654+004280,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000401,sig:06,src:010146,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000426,sig:06,src:010172,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000543,sig:06,src:009545+009910,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000570,sig:06,src:010106,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000232,sig:11,src:009839,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000547,sig:06,src:010493+010044,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave4/crashes/id:000279,sig:11,src:010165,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000336,sig:11,src:009967,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000434,sig:06,src:010511,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000375,sig:11,src:009537+010502,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000267,sig:06,src:009803,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000381,sig:11,src:010372,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000274,sig:06,src:009816,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000218,sig:11,sync:slave2,src:009579",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000473,sig:11,src:000064+009924,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000324,sig:11,src:009910,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000431,sig:11,src:009771+010082,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000258,sig:06,src:009851,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000314,sig:11,src:009694,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000403,sig:06,src:009839,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000476,sig:06,src:010089+010096,op:splice,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000276,sig:11,src:010019,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000561,sig:06,src:010305+010189,op:splice,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000082,sig:06,src:005658,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000548,sig:06,src:008598+008956,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000353,sig:11,src:008531+010008,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000400,sig:06,src:010033,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000281,sig:11,src:009794+006971,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000391,sig:06,src:009911,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave6/crashes/id:000321,sig:06,src:010050,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave0/crashes/id:000394,sig:11,src:009930,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave0/crashes/id:000326,sig:06,src:009519,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave0/crashes/id:000332,sig:06,src:009465,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave0/crashes/id:000525,sig:06,src:009974+009663,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave0/crashes/id:000287,sig:06,src:009473,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave0/crashes/id:000163,sig:06,src:006224+005467,op:splice,rep:128",
            "/home/happy/afl_chengang2/tmp/findings/slave0/crashes/id:000011,sig:11,src:000503,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/master/crashes/id:000154,sig:06,sync:slave5,src:010116",
            "/home/happy/afl_chengang2/tmp/findings/master/crashes/id:000185,sig:06,src:006837,op:arith8,pos:72,val:+11",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000310,sig:06,src:009903,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000495,sig:06,src:009719,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000048,sig:11,src:000241+001445,op:splice,rep:64",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000492,sig:06,src:009794,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000235,sig:06,src:009933+009085,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000370,sig:06,src:010015,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000325,sig:06,src:009884,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000242,sig:11,src:009118+009413,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000420,sig:11,src:009598,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000311,sig:06,src:010151,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000496,sig:06,src:010190,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000366,sig:06,src:009889,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000299,sig:06,src:009713,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000357,sig:11,src:009861,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000271,sig:06,src:009346+009796,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000487,sig:06,src:010214+010103,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000306,sig:06,src:009915,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000410,sig:06,src:009751,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000347,sig:06,src:009766,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000605,sig:06,src:010081+006488,op:splice,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000521,sig:11,src:010559,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000258,sig:11,src:004028+010017,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000578,sig:06,src:010739+010123,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000491,sig:06,src:009886,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000489,sig:11,src:009591,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000227,sig:06,src:009706,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000355,sig:06,src:008184+009917,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000387,sig:06,src:010163,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000475,sig:06,src:009946,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000575,sig:06,src:008462+009631,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000453,sig:06,src:010007+000283,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000412,sig:06,src:009898,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000211,sig:11,src:009316,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000344,sig:06,src:010165,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000323,sig:06,src:009731,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000406,sig:06,src:009489,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000411,sig:06,src:010187,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000599,sig:06,src:009937,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000249,sig:11,src:009393,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000537,sig:06,src:009841,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000348,sig:06,src:010148,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000309,sig:06,src:009725+000156,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000398,sig:06,src:010138,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000315,sig:06,src:009719,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000400,sig:06,src:009719,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000359,sig:06,src:010071,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000243,sig:11,src:009964,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000534,sig:06,src:009794,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000557,sig:06,src:009817,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000332,sig:11,src:010280,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000516,sig:06,src:009957+000436,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000508,sig:06,src:009942+010215,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000456,sig:06,src:009999,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000367,sig:11,src:010109+003087,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000423,sig:06,src:008295,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000566,sig:11,src:010163,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000316,sig:06,src:010109+010034,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000351,sig:11,src:009358,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000230,sig:06,src:009802,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000223,sig:11,src:000835+009477,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000213,sig:06,src:009370,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000236,sig:06,src:009946,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave2/crashes/id:000210,sig:11,src:009298,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000303,sig:06,src:010115,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000287,sig:06,src:010086,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000278,sig:06,src:010005,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000389,sig:06,src:010190,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000078,sig:11,src:004569+002250,op:splice,rep:32",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000353,sig:06,src:010086,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000320,sig:06,src:010080,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000599,sig:11,src:010657,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000406,sig:11,src:010215,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000343,sig:11,src:009413,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000352,sig:11,src:009776,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000334,sig:06,src:010278,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000625,sig:06,src:010639+009401,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000375,sig:11,src:009485,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000675,sig:06,src:010041+009607,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000387,sig:11,src:009790,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000333,sig:06,src:010023,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000272,sig:11,src:009587,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000481,sig:11,src:009738,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000402,sig:06,src:009975,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000269,sig:11,src:009529,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000518,sig:06,src:010544,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000643,sig:06,src:009813+006990,op:splice,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000477,sig:11,src:009375+009407,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000555,sig:11,src:009988+010110,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000507,sig:11,src:009631,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000456,sig:06,src:009860+010021,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000056,sig:11,src:000288+001596,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000432,sig:11,src:002790+010110,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000510,sig:06,src:009852,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000321,sig:06,src:009787,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000496,sig:06,src:010229,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000635,sig:06,src:010167,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000572,sig:11,src:008152+010083,op:splice,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000506,sig:11,src:008105+009918,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000541,sig:11,src:010384+009389,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000312,sig:11,src:009886,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000408,sig:11,src:007584+009873,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000405,sig:11,src:010174,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000462,sig:06,src:009890+009707,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000362,sig:11,src:010004,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000619,sig:06,src:009554,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000249,sig:11,src:009456,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000550,sig:11,src:009964,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000452,sig:06,src:010030,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000515,sig:06,src:009922,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000504,sig:06,src:009467+002993,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000517,sig:11,src:010614,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000598,sig:06,src:010003+010191,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000311,sig:06,src:009822,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000413,sig:06,src:010101,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000328,sig:06,src:009519,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000449,sig:06,src:009528,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000316,sig:11,src:009486,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000378,sig:11,src:009689,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000388,sig:06,src:010101,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000489,sig:06,src:009926,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000530,sig:06,src:010280,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000478,sig:11,src:009800,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000486,sig:06,src:008204,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000463,sig:06,src:009974,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000373,sig:06,src:009993,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000301,sig:06,src:009765,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000370,sig:11,src:009534,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000632,sig:06,src:009966+009132,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000310,sig:06,src:009513+010094,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000422,sig:06,src:010156,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000302,sig:06,src:010111,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000404,sig:06,src:010127,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000564,sig:11,src:001842+010161,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000365,sig:06,src:009992,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000495,sig:06,src:010202,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000376,sig:11,src:009504+009555,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000658,sig:06,src:009949+010050,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000630,sig:06,src:006581+009816,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000414,sig:11,src:009494,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000364,sig:11,src:002120+009777,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000546,sig:06,src:009866,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000323,sig:06,src:010108,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000377,sig:11,src:009534,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave3/crashes/id:000574,sig:06,src:010017,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000343,sig:11,src:009590+006769,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000309,sig:06,src:009313,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000323,sig:11,src:009386,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000333,sig:11,src:005564+009826,op:splice,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000412,sig:06,src:009269,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000195,sig:11,src:009271,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000239,sig:06,src:009410,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000196,sig:11,src:009367,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000279,sig:06,src:010063,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000179,sig:11,src:009274,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000215,sig:11,src:009612+008172,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000391,sig:06,src:009429,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000350,sig:11,src:009663,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000175,sig:11,src:001917+009276,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000265,sig:06,src:009372,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000365,sig:11,src:009420,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000295,sig:11,src:009552,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000223,sig:11,src:009253,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000415,sig:11,src:009355+006033,op:splice,rep:64",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000074,sig:06,src:003215,op:havoc,rep:8",
            "/home/happy/afl_chengang2/tmp/findings/slave7/crashes/id:000168,sig:11,src:001436+009442,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave1/crashes/id:000352,sig:11,src:009546,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave1/crashes/id:000435,sig:06,src:009888+009463,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave1/crashes/id:000164,sig:11,src:009475,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave1/crashes/id:000264,sig:11,src:000333+009954,op:splice,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave1/crashes/id:000327,sig:11,src:009482,op:havoc,rep:2",
            "/home/happy/afl_chengang2/tmp/findings/slave1/crashes/id:000082,sig:06,src:005388,op:havoc,rep:4",
            "/home/happy/afl_chengang2/tmp/findings/slave1/crashes/id:000293,sig:11,src:010258,op:havoc,rep:2",
        ]

        print( "total ", len(items), " files found.")

        event_loop = asyncio.get_event_loop()

        try:
            futures = []

            n = 0
            k = 0;
            for fname in items:
                n += 1
                k += 1

                args = [self.exe_name, fname]
                futures.append(asyncio.ensure_future(self.run_command_async(n, *args)))

                if k >= self.job_limit:
                    event_loop.run_until_complete(asyncio.gather(*futures))
                    futures.clear()
                    k = 0;

                # if (n > 2000):
                #     break

            if len(futures) > 0:
                event_loop.run_until_complete(asyncio.gather(*futures))
        finally:
            event_loop.close()

        print("count = ", len(self.timeouted), ", timeout")
        for fname in self.timeouted:
            print("    ", fname)


def main(argv=None):
    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    # Setup argument parser
    parser = ArgumentParser(description="AFL hang analyzer)",
                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument("-e", "--exe", dest="exe", action="store",  default="/home/happy/afl_chengang/build/bin/wavm",
                        help="Exe name to run")
    parser.add_argument("-j", "--job", dest="job", action="store", type=int, default=1,
                        help="Job limit")

    args = parser.parse_args()

    if args.exe and args.job:

        fdf = FileDuplicateFinder(args.exe, args.job)
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